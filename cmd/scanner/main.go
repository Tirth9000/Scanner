package main

import (
	"context"
	"encoding/json"
	"fmt"

	"scanner-platform/scanner-engine/core"
	"scanner-platform/scanner-engine/scanners/collection"
	"scanner-platform/scanner-engine/scanners/discovery"
	"scanner-platform/scanner-engine/scanners/filters"
)

func main() {
	ctx := context.Background()
	// domain_name := "vulnweb.com"
	// domain_name := "officebeacon.com"
	domain_name := "allianzcloud.com"
	// domain_name := "flowzstaffing.com"

	fmt.Println("Starting scanning for domain:", domain_name)
	fmt.Println("Scanner 1 : Subdomain Discovery")

	registry := core.NewRegistry()

	// registry.Register(discovery.NewDNSScanner())
	registry.Register(discovery.NewCrtCTScanner())
	registry.Register(discovery.NewCertSpotterCTScanner())
	registry.Register(discovery.NewSubdomainBruteforceScanner())
	registry.Register(discovery.NewSubdomainSubFinderScanner())

	pipeline := core.NewDiscoveryPipeline(registry)

	results, err := pipeline.ExecuteDiscoveryScanner(ctx, domain_name)

	if err != nil {
		panic(err)
	}

	fmt.Println("Total Subdomains Found:", len(results.Data.([]string)))

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

	fmt.Println("Total Filtered Subdomains Found:", filtered_results.Data)
	fmt.Println(filtered_results)

	fmt.Println("Scanner 3 : Data Collection")

	collection_registry := core.NewCollectionRegistry()

	collection_registry.RegisterCollectionScanner(collection.NewDNSDataOutput())
	collection_registry.RegisterCollectionScanner(collection.NewHTTPXFilterOutput())
	collection_registry.RegisterCollectionScanner(collection.NewPortFilter())
	// collection_registry.RegisterCollectionScanner(collection.NewServiceDetectionScanner())
	collection_registry.RegisterCollectionScanner(collection.NewTLSDataCollection())
	collection_registry.RegisterCollectionScanner(collection.NewMailSecurityDataCollection())

	collection_pipeline := core.NewCollectionPipeline(collection_registry)

	collection_pipeline_results, err := collection_pipeline.ExecuteCollectionScanenrs(ctx, filtered_results, domain_name)
	if err != nil {
		panic(err)
	}

	// for _, r := range collection_pipeline_results.Data.([]interface{}) {

	// 	data, err := json.MarshalIndent(r, "", "  ")
	// 	if err != nil {
	// 		fmt.Println("error:", err)
	// 		continue
	// 	}

	// 	fmt.Println(string(data))
	// }

	dataMap, ok := collection_pipeline_results.Data.(map[string]interface{})
	if !ok {
		fmt.Println("Invalid data format")
		return
	}

	// -------- HOST --------
	if host, ok := dataMap["host"]; ok {

		hostJSON, err := json.MarshalIndent(host, "", "  ")
		if err != nil {
			fmt.Println("host marshal error:", err)
		} else {
			fmt.Println("===== HOST =====")
			fmt.Println(string(hostJSON))
		}
	}

	// -------- SUBDOMAINS --------
	if subs, ok := dataMap["subdomains"].([]interface{}); ok {

		fmt.Println("===== SUBDOMAINS =====")

		for _, r := range subs {

			data, err := json.MarshalIndent(r, "", "  ")
			if err != nil {
				fmt.Println("error:", err)
				continue
			}

			fmt.Println(string(data))
		}
	}
}
