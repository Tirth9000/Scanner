package worker

import (
	"context"
	"fmt"
	"log"
	"strconv"

	"scanner-platform/internal/models"
	"scanner-platform/scanner-engine/core"
	"scanner-platform/scanner-engine/scanners/collection"
	"scanner-platform/scanner-engine/scanners/discovery"
	"scanner-platform/scanner-engine/scanners/filters"
)

func Run(ctx context.Context, job *models.ScanJob) ([]core.Result, error) {

	log.Printf("Scan started: %s (%s)", job.ScanID, job.Target)

	fmt.Println("Pipeline started for domain:", job.Target)

	fmt.Println("Pipeline 1 : subdomain discovery")

	registry := core.NewRegistry()

	registry.Register(discovery.NewDNSScanner())
	registry.Register(discovery.NewCrtCTScanner())
	registry.Register(discovery.NewCertSpotterCTScanner())
	registry.Register(discovery.NewSubdomainBruteforceScanner())
	registry.Register(discovery.NewSubdomainSubFinderScanner())

	pipeline := core.NewPipeline(registry)

	results, err := pipeline.Execute(ctx, job.Target)
	if err != nil {
		return nil, err
	}

	discovery_payload := map[string]string{
		"scan_id": job.ScanID,
		"target":  job.Target,
		"event":   "subdomain_discovery_completed",
		"data":    strconv.Itoa(len(results)),
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

	filter_payload := map[string]string{
		"scan_id": job.ScanID,
		"target":  job.Target,
		"event":   "subdomain_filter_completed",
		"data":    strconv.Itoa(len(filter_pipeline_results)),
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

    collection_payload := map[string]string{
		"scan_id": job.ScanID,
		"target":  job.Target,
		"event":   "subdomain_collection_completed",
		"data":    strconv.Itoa(len(collection_data_results)),
	}
	collection_res, err := send_webhook_notification(collection_payload)
	if err != nil {
		log.Printf("Failed to send webhook notification: %v", err)
	}

	fmt.Println("Total Results Found:", len(collection_data_results), collection_res)

	return collection_data_results, nil
}
