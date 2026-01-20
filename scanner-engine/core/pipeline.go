package core

import (
	"context"
	"fmt"
)

type Pipeline struct {
	registry *Registry
	runner *Runner
}

func NewPipeline(registry *Registry) *Pipeline {
	return &Pipeline{
		registry: registry,
		runner: NewRunner(),
	}
}

func (p *Pipeline) Execute(ctx context.Context, target string) ([]Result, error) {
	var results []Result

	fmt.Println("Starting discovery pipeline for target:", target)

	for _, scanner := range p.registry.All() {
		fmt.Println("Running scanner:", scanner.Name())
		res, err := p.runner.Run(ctx, scanner, target)
		if err != nil {
			fmt.Println("Scanner error:", scanner.Name(), err)
			continue
		}
		results = append(results, res...)
		fmt.Println("Completed scanner:", scanner.Name())
		fmt.Println("Total results so far:", len(results))
	}

	return results, nil
}


type FilterScannerPipeline struct {
	registry *FilterScannerRegistry
	runner *Runner
}

func NewFilterPipeline(registry *FilterScannerRegistry) *FilterScannerPipeline {
	return &FilterScannerPipeline{
		registry: registry,
		runner: NewRunner(),
	}
}

func (p *FilterScannerPipeline) ExecuteFilterScanners(ctx context.Context, subdomains []Result, domain string) ([]Result, error) {
	fmt.Println("Starting filter pipeline for domain:", domain)

	for _, scanner := range p.registry.All() {
		fmt.Println("Running filter scanner:", scanner.Name())
		res, err := p.runner.RunFilterScanners(ctx, scanner, subdomains, domain)
		if err != nil {
			fmt.Println("Filter scanner error:", scanner.Name(), err)
			continue
		}
		fmt.Println("Completed filter scanner:", scanner.Name())
		fmt.Println("Total subdomains so far:", len(res))
		
		subdomains = res
	}
	
	return subdomains, nil
}


type CollectionPipeline struct {
	registry *CollectionScannerRegistry
	runner *Runner
}

func NewCollectionPipeline(registry *CollectionScannerRegistry) *CollectionPipeline {
	return &CollectionPipeline{
		registry: registry,
		runner: NewRunner(),
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
