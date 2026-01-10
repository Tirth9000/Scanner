package discovery

import (
	"context"
	"strings"
	"time"
	"fmt"
	"os"

	"scanner-platform/scanner/core"
)

type SubdomainChaosScanner struct{}

func NewSubdomainChaosScanner() *SubdomainChaosScanner {
	return &SubdomainChaosScanner{}
}

func (c *SubdomainChaosScanner) Name() string {
	return "subdomain_chaos"
}

func (c *SubdomainChaosScanner) Category() string {
	return "discovery"
}

func (c *SubdomainChaosScanner) Run(ctx context.Context, domain string) ([]core.Result, error) {
	domain_name := strings.Split(domain, ".")[0]
	domain_file, err := os.ReadDir("scanners/discovery/AllChaosData/" + domain_name)
	if err != nil {
		return nil, err
	}

	var results []core.Result

	for _, file := range domain_file {
		if strings.Split(file.Name(), ".txt")[0] == domain {
			subdomains, err := os.ReadFile("scanners/discovery/AllChaosData/" + domain_name + "/" + file.Name())
			if err != nil {
				return nil, err
			}

			for _, subdomain := range strings.Split(string(subdomains), "\n") {
				if !IsValidSubdomain(string(subdomain), domain) {
					continue
				}
				
				results = append(results, core.Result{
					Scanner: c.Name(),
					Category: c.Category(),
					Target: domain,
					Data: map[string]string{
						"subdomain": string(subdomain),
						"method": "chaos_data",
					},
					Severity: "info",
					Timestamp:  time.Now(),
					},
				)
			}
		}
	}
	fmt.Println(len(results))
	return results, nil
}	