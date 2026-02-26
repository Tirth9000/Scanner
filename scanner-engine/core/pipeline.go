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

func (p *DiscoveryPipeline) Execute(ctx context.Context, target string) (ScanResult, error) {
	var results []string

	ips, err := net.LookupIP(target)
	if err != nil || len(ips) == 0 {
		return ScanResult{}, err
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

	subdomainsFound := ScanResult{
		ScanID:    "1234",
		Target:    target,
		Data:      results,
		Timestamp: time.Now(),
	}

	return subdomainsFound, nil
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

func (p *FilterScannerPipeline) ExecuteFilterScanners(ctx context.Context, discovered_subdomains ScanResult, domain string) (ScanResult, error) {
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

	filtered_subdomains := ScanResult{
		ScanID:    "1234",
		Target:    domain,
		Data:      subdomains.Data,
		Timestamp: time.Now(),
	}

	fmt.Println(filtered_subdomains)
	fmt.Println(len(filtered_subdomains.Data.([]string)))
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

func (c *CollectionPipeline) ExecuteCollectionScanenrs(ctx context.Context, data_collected []Result, domain string) ([]Result, error) {
	fmt.Println("Starting collection pipeline for domain:", domain)

	for _, scanner := range c.registry.All() {
		fmt.Println("Running collection scanner:", scanner.Name())
		res, err := c.runner.RunCollectionScanners(ctx, scanner, data_collected, domain)
		if err != nil {
			fmt.Println("Collection scanner error:", scanner.Name(), err)
		}

		fmt.Println("Completed collection scanner:", scanner.Name())

		data_collected = res
	}
	fmt.Println("Total data collected so far:", len(data_collected))

	return data_collected, nil
}
