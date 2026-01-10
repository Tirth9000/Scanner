package scanner

import (
	"context"
	"fmt"

	"scanner-platform/scanner-engine/core"
	"scanner-platform/scanner-engine/scanners/collection"
	"scanner-platform/scanner-engine/scanners/discovery"
	"scanner-platform/scanner-engine/scanners/filters"
)

func main() {
	ctx := context.Background()

	registry := core.NewRegistry()

	registry.Register(discovery.NewDNSScanner())
	// registry.Register(discovery.NewCrtCTScanner())
	// registry.Register(discovery.NewCertSpotterCTScanner())
	// registry.Register(discovery.NewSubdomainBruteforceScanner())
	registry.Register(discovery.NewSubdomainSubFinderScanner())

	pipeline := core.NewPipeline(registry)

	results, err := pipeline.Execute(ctx, "allianzcloud.com")
	// results, err := pipeline.Execute(ctx, "example.com")
	// results, err := pipeline.Execute(ctx, "google.com")
	if err != nil {
		panic(err)
	}

	fmt.Println("final result count : ", len(results))

	filter_registry := core.NewFilterScannerRegistry()

	filter_registry.RegisterFilterScanner(filters.NewDedupFilter())
	filter_registry.RegisterFilterScanner(filters.NewDNSFilter())
	filter_registry.RegisterFilterScanner(filters.NewHTTPFilter())
	filter_registry.RegisterFilterScanner(collection.NewHTTPXFilterOutput())
	filter_registry.RegisterFilterScanner(collection.NewPortFilter())
	// filter_registry.RegisterFilterScanner(filters.NEWDNSTEST()) // test dns

	filter_pipeline := core.NewFilterPipeline(filter_registry)

	// filtered_results, err := filter_pipeline.ExecuteFilterScanners(ctx, results, "example.com")
	// filtered_results, err := filter_pipeline.ExecuteFilterScanners(ctx, results, "google.com")
	filtered_results, err := filter_pipeline.ExecuteFilterScanners(ctx, results, "allianzcloud.com")
	if err != nil {
		panic(err)
	}

	for _, r := range filtered_results {
		fmt.Printf("%+v\n", r)
	}
	
	fmt.Println(len(filtered_results))
}
