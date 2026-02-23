package worker

import (
	"context"
	"fmt"
	"log"
	"strconv"
	"time"

	"scanner-platform/internal/models"
	"scanner-platform/scanner-engine/core"
	"scanner-platform/scanner-engine/scanners/collection"
	"scanner-platform/scanner-engine/scanners/discovery"
	"scanner-platform/scanner-engine/scanners/filters"
)

func Run(ctx context.Context, job *models.ScanJob) (any, error) {

	log.Printf("Scan started: %s (%s)", job.ScanID, job.Target)

	fmt.Println("Pipeline started for domain:", job.Target)

	fmt.Println("Pipeline 1 : subdomain discovery")

	registry := core.NewRegistry()

	registry.Register(discovery.NewDNSScanner())
	registry.Register(discovery.NewCrtCTScanner())
	registry.Register(discovery.NewCertSpotterCTScanner())
	registry.Register(discovery.NewSubdomainBruteforceScanner())
	// registry.Register(discovery.NewSubdomainSubFinderScanner())

	pipeline := core.NewPipeline(registry)

	results, err := pipeline.Execute(ctx, job.Target)
	if err != nil {
		return nil, err
	}

	discovery_payload := models.ScanNotification{
		ScanID: job.ScanID,
		Target:  job.Target,
		Event:   "subdomain_discovery_completed",
		Data:    strconv.Itoa(len(results)),
	}
	discovery_res, err := send_webhook_notification(discovery_payload)
	if err != nil {
		log.Printf("Failed to send webhook notification: %v", err)
	}

	fmt.Println("Total Subdomains Found:", len(results), discovery_res)

	fmt.Println("Pipeline 2 : filter subdomain")

	filter_registry := core.NewFilterScannerRegistry()

	filter_registry.RegisterFilterScanner(filters.NewDedupFilter())
	filter_registry.RegisterFilterScanner(filters.NewDNSFilter())
	filter_registry.RegisterFilterScanner(filters.NewHTTPFilter())

	filter_pipeline := core.NewFilterPipeline(filter_registry)

	filter_pipeline_results, err := filter_pipeline.ExecuteFilterScanners(ctx, results, job.Target)
	if err != nil {
		return nil, err
	}

	filter_payload := models.ScanNotification{
		ScanID: job.ScanID,
		Target:  job.Target,
		Event:   "subdomain_filter_completed",
		Data:    strconv.Itoa(len(filter_pipeline_results)),
	}
	filter_res, err := send_webhook_notification(filter_payload)
	if err != nil {
		log.Printf("Failed to send webhook notification: %v", err)
	}

	fmt.Println("Total Filtered Subdomains Found:", len(filter_pipeline_results), filter_res)

	fmt.Println("Scanner 3 : Data collection")

	collection_registry := core.NewCollectionRegistry()

	collection_registry.RegisterCollectionScanner(collection.NewHTTPXFilterOutput())
	collection_registry.RegisterCollectionScanner(collection.NewPortFilter())
	collection_registry.RegisterCollectionScanner(collection.NewTLSDataCollection())

	collection_pipeline := core.NewCollectionPipeline(collection_registry)

	collection_data_results, err := collection_pipeline.ExecuteCollectionScanenrs(ctx, filter_pipeline_results, job.Target)
	if err != nil {
		return nil, err
	}

	collection_payload := models.ScanNotification{
		ScanID: job.ScanID,
		Target:  job.Target,
		Event:   "subdomain_collection_completed",
		Data:    strconv.Itoa(len(collection_data_results)),
	}

	collection_res, err := send_webhook_notification(collection_payload)
	if err != nil {
		log.Printf("Failed to send webhook notification: %v", err)
	}

	fmt.Println("Total Results Found:", len(collection_data_results), collection_res)

	scanResult := []models.ScanResult{}
	data := []any{}

	for _, res := range collection_data_results {
		data = append(data, res.Data)
	}
	
	scanResult = append(scanResult, models.ScanResult{
			ScanID: job.ScanID,
			Target: job.Target,
			Data:   data,
			Timestamp: time.Now(),
	})

	res, err := send_scan_result_webhook(scanResult[0])

	return res, nil
}
