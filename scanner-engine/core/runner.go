package core

import (
	"context"
)

type Runner struct{}

func NewRunner() *Runner {
	return &Runner{}
}

func (r *Runner) Run(ctx context.Context,
	scanner Scanner,
	target string,
) ([]Result, error) {
	return scanner.Run(ctx, target)
}

func (r *Runner) RunFilterScanners(ctx context.Context, 
	scanner FilterScanner, 
	subdomains []Result,
	domain string,
) ([] Result, error){
	return scanner.RunFilterScanner(ctx, subdomains, domain)
}