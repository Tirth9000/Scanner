package core

import "context"

type Scanner interface {
	Name() string
	Category() string
	Run(ctx context.Context, target string) ([]Result, error)
}

type FilterScanner interface {
	Name() string
	Category() string
	RunFilterScanner(ctx context.Context, subdomains []Result, domain string) ([]Result, error)
}

type CollectionScanners interface{
	Name() string
	Category() string
	RunCollectionScanner(ctx context.Context, subdomains []Result, domain string) ([]Result, error)
}