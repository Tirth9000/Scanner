package core

import "context"

type DiscoveryScanner interface {
	Name() string
	Category() string
	RunDiscoveryScanner(ctx context.Context, target string) (ScanResult, error)
}

type FilterScanner interface {
	Name() string
	Category() string
	RunFilterScanner(ctx context.Context, subdomains ScanResult, domain string) (ScanResult, error)
}

type CollectionScanners interface{
	Name() string
	Category() string
	RunCollectionScanner(ctx context.Context, subdomains []Result, domain string) ([]Result, error)
}