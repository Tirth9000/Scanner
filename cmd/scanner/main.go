package main

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
	domain_name := "cloudflare.com"

	fmt.Println("Starting scanning for domain:", domain_name)
	fmt.Println("Scanner 1 : Subdomain Discovery")

	registry := core.NewRegistry()

	registry.Register(discovery.NewDNSScanner())
	registry.Register(discovery.NewCrtCTScanner())
	registry.Register(discovery.NewCertSpotterCTScanner())
	registry.Register(discovery.NewSubdomainBruteforceScanner())
	registry.Register(discovery.NewSubdomainSubFinderScanner())

	pipeline := core.NewPipeline(registry)

	results, err := pipeline.Execute(ctx, domain_name)

	if err != nil {
		panic(err)
	}

	fmt.Println("Total Subdomains Found:", len(results))

	fmt.Println("Scanner 2 : Subdomain Filter")

	filter_registry := core.NewFilterScannerRegistry()

	filter_registry.RegisterFilterScanner(filters.NewDedupFilter())
	filter_registry.RegisterFilterScanner(filters.NewDNSFilter())
	filter_registry.RegisterFilterScanner(filters.NewHTTPFilter())

	// filter_registry.RegisterFilterScanner(filters.NEWDNSTEST()) // test dns

	filter_pipeline := core.NewFilterPipeline(filter_registry)

	filtered_results, err := filter_pipeline.ExecuteFilterScanners(ctx, results, domain_name)
	if err != nil {
		panic(err)
	}

	fmt.Println("Total Filtered Subdomains Found:", len(filtered_results))

	fmt.Println("Scanner 3 : Data Collection")

	collection_registry := core.NewCollectionRegistry()

	collection_registry.RegisterCollectionScanner(collection.NewHTTPXFilterOutput())
	collection_registry.RegisterCollectionScanner(collection.NewPortFilter())
	collection_registry.RegisterCollectionScanner(collection.NewTLSDataCollection())

	collection_pipeline := core.NewCollectionPipeline(collection_registry)

	collection_pipeline_results, err := collection_pipeline.ExecuteCollectionScanenrs(ctx, filtered_results, domain_name)	
	if err != nil {
		panic(err)
	}

	fmt.Println("Final Results:")
	for _, r := range collection_pipeline_results {
		fmt.Printf("%+v\n", r)
	}
	fmt.Println("Total Results Found:", len(collection_pipeline_results))
}
