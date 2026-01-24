package worker

import (
	"context"
	"fmt"
	"log"

	"scanner-platform/internal/models"
	// "scanner-platform/internal/webhook"
	"scanner-platform/scanner-engine/core"
	"scanner-platform/scanner-engine/scanners/discovery"
	"scanner-platform/scanner-engine/scanners/filters"
    "scanner-platform/scanner-engine/scanners/collection"
)

func Run(ctx context.Context, job *models.ScanJob) {
    log.Printf("Scan started: %s (%s)", job.ScanID, job.Domain)

    fmt.Println("Pipeline started for domain:", job.Domain)

    fmt.Println("Pipeline 1 : subdomain discovery")

    registry := core.NewRegistry()

    registry.Register(discovery.NewDNSScanner())
    registry.Register(discovery.NewCrtCTScanner())
    registry.Register(discovery.NewCertSpotterCTScanner())
    registry.Register(discovery.NewSubdomainBruteforceScanner())
    registry.Register(discovery.NewSubdomainSubFinderScanner())

    pipeline := core.NewPipeline(registry)

    results, err := pipeline.Execute(ctx, job.Domain)
    if err != nil {
        panic(err)
    }

    fmt.Println("Total Subdomains Found:", len(results))

    fmt.Println("Pipeline 2 : filter subdomain")

    filter_registry := core.NewFilterScannerRegistry()

    filter_registry.RegisterFilterScanner(filters.NewDedupFilter())
    filter_registry.RegisterFilterScanner(filters.NewDNSFilter())
    filter_registry.RegisterFilterScanner(filters.NewHTTPFilter())

    filter_pipeline := core.NewFilterPipeline(filter_registry)

    filter_pipeline_results, err := filter_pipeline.ExecuteFilterScanners(ctx, results, job.Domain)
    if err != nil {
        panic(err)
    }

    fmt.Println("Total Filtered Subdomains Found:", len(filter_pipeline_results))

    fmt.Println("Scanner 3 : Data collection")

    collection_registry := core.NewCollectionRegistry()

    collection_registry.RegisterCollectionScanner(collection.NewHTTPXFilterOutput())
    collection_registry.RegisterCollectionScanner(collection.NewPortFilter())
    collection_registry.RegisterCollectionScanner(collection.NewTLSDataCollection())

    collection_pipeline := core.NewCollectionPipeline(collection_registry)

    collecgtion_data_results, err := collection_pipeline.ExecuteCollectionScanenrs(ctx, filter_pipeline_results, job.Domain)
    if err != nil {
        panic(err)
    }

    // fmt.Println("Final Results:")
    // for _, r := range collecgtion_data_results {
    //     fmt.Printf("%+v\n", r)
    // }
    fmt.Println("Total Results Found:", len(collecgtion_data_results))

    // webhook.Send(job.ScanID, "scan_started", nil)

    // pipeline := scanner.NewPipeline(job.Domain)

    // for stage := range pipeline.Execute(ctx) {
    //     webhook.Send(job.ScanID, stage.Name, stage.Data)
    // }

    // webhook.Send(job.ScanID, "scan_completed", nil)
}