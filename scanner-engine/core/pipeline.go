package core

import (
	"context"
	"fmt"
)

type Pipeline struct {
	registry *Registry
	runner *Runner
}

type FilterScannerPipeline struct {
	registry *FilterScannerRegistry
	runner *Runner
}

func NewPipeline(registry *Registry) *Pipeline {
	return &Pipeline{
		registry: registry,
		runner: NewRunner(),
	}
}

func NewFilterPipeline(registry *FilterScannerRegistry) *FilterScannerPipeline {
	return &FilterScannerPipeline{
		registry: registry,
		runner: NewRunner(),
	}
}

func (p *Pipeline) Execute(ctx context.Context, target string) ([]Result, error) {
	var results []Result

	fmt.Println("Starting pipeline for target:", target)

	for _, scanner := range p.registry.All() {
		fmt.Println("Running scanner:", scanner.Name())
		res, err := p.runner.Run(ctx, scanner, target)
		if err != nil {
			fmt.Println("Scanner error:", scanner.Name(), err)
			continue
		}
		results = append(results, res...)
		fmt.Println("Completed scanner:", scanner.Name())
	}

	return results, nil
}

func (p *FilterScannerPipeline) ExecuteFilterScanners(ctx context.Context, subdomains []Result, domain string) ([]Result, error) {

	for _, scanner := range p.registry.All() {
		fmt.Println("Running filter scanner:", scanner.Name())
		res, err := p.runner.RunFilterScanners(ctx, scanner, subdomains, domain)
		if err != nil {
			fmt.Println("Filter scanner error:", scanner.Name(), err)
		}
		
		subdomains = res
	}
	
	return subdomains, nil
}