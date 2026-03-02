package core

import (
	"context"
	"fmt"
	"net"
	"time"
)

type DiscoveryPipeline struct {
	registry *Registry
	runner   *Runner
}

func NewDiscoveryPipeline(registry *Registry) *DiscoveryPipeline {
	return &DiscoveryPipeline{
		registry: registry,
		runner:   NewRunner(),
	}
}

func (p *DiscoveryPipeline) ExecuteDiscoveryScanner(ctx context.Context, target string) (Result, error) {
	var results []string

	ips, err := net.LookupIP(target)
	if err != nil || len(ips) == 0 {
		return Result{}, err
	}

	fmt.Println("Starting discovery pipeline for target:", target)

	for _, scanner := range p.registry.All() {
		fmt.Println("Running scanner:", scanner.Name())
		res, err := p.runner.RunDiscoveryScanner(ctx, scanner, target)
		if err != nil {
			fmt.Println("Scanner error:", scanner.Name(), err)
			continue
		}
		data := res.Data.([]string)
		results = append(results, data...)
		fmt.Println("Completed scanner:", scanner.Name())
		fmt.Println("Total results so far:", len(results))
	}

	discovered_subdomains := Result{
		Scanner:   "discovery_pipeline",
		Category:  "discovery",
		Target:    target,
		Data:      results,
		Timestamp: time.Now(),
	}

	// fmt.Println(discovered_subdomains)

	return discovered_subdomains, nil
}

type FilterScannerPipeline struct {
	registry *FilterScannerRegistry
	runner   *Runner
}

func NewFilterPipeline(registry *FilterScannerRegistry) *FilterScannerPipeline {
	return &FilterScannerPipeline{
		registry: registry,
		runner:   NewRunner(),
	}
}

func (p *FilterScannerPipeline) ExecuteFilterScanners(ctx context.Context, discovered_subdomains Result, domain string) (Result, error) {
	fmt.Println("Starting filter pipeline for domain:", domain)
	subdomains := discovered_subdomains

	for _, scanner := range p.registry.All() {
		fmt.Println("Running filter scanner:", scanner.Name())
		res, err := p.runner.RunFilterScanners(ctx, scanner, subdomains, domain)
		if err != nil {
			fmt.Println("Filter scanner error:", scanner.Name(), err)
			continue
		}
		fmt.Println("Completed filter scanner:", scanner.Name())
		fmt.Println("Total subdomains so far:", len(res.Data.([]string)))

		subdomains = res
	}

	var data []interface{}

	for _, subdomain := range subdomains.Data.([]string) {
		var filter_structured_subdomains = make(map[string]any)
		filter_structured_subdomains["subdomain"] = subdomain
		data = append(data, filter_structured_subdomains)
	}

	filtered_subdomains := Result{
		Scanner:   "filter_pipeline",
		Category:  "filter",
		Target:    domain,
		Data:      data,
		Timestamp: time.Now(),
	}

	return filtered_subdomains, nil
}

type CollectionPipeline struct {
	registry *CollectionScannerRegistry
	runner   *Runner
}

func NewCollectionPipeline(registry *CollectionScannerRegistry) *CollectionPipeline {
	return &CollectionPipeline{
		registry: registry,
		runner:   NewRunner(),
	}
}

func (c *CollectionPipeline) ExecuteCollectionScanenrs(ctx context.Context, subdomains Result, domain string) (Result, error) {
	fmt.Println("Starting collection pipeline for domain:", domain)
	
	for _, scanner := range c.registry.All() {
		fmt.Println("Running collection scanner:", scanner.Name())
		res, err := c.runner.RunCollectionScanners(ctx, scanner, subdomains, domain)
		if err != nil {
			fmt.Println("Collection scanner error:", scanner.Name(), err)
		}

		fmt.Println("Completed collection scanner:", scanner.Name())

		subdomains = res
	}
	// fmt.Println("Total data collected so far:", len(data_collected))

	return subdomains, nil
}
