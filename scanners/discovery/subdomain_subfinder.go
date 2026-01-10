package discovery

import (
	"bufio"
	"context"
	"os/exec"
	"strings"
	"time"

	"scanner-platform/scanner/core"
)

type SubdomainSubFinderScanner struct{}

func NewSubdomainSubFinderScanner() *SubdomainSubFinderScanner {
	return &SubdomainSubFinderScanner{}
}

func (s *SubdomainSubFinderScanner) Name() string {
	return "subdomain_subfinder"
}

func (s *SubdomainSubFinderScanner) Category() string {
	return "discovery"
}

func (s * SubdomainSubFinderScanner) Run(ctx context.Context, domain string) ([]core.Result, error) {
	cmd := exec.CommandContext(
		ctx,
		"subfinder",
		"-silent",
		"-d", domain,
	)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}

	if err := cmd.Start(); err != nil {
		return nil, err
	}

	scanner := bufio.NewScanner(stdout)
	seen := make(map[string]struct{})
	var results []core.Result

	for scanner.Scan() {
		sub := strings.TrimSpace(scanner.Text())

		// if !IsValidSubdomain(sub, domain) {
		// 	continue
		// }

		if _, ok := seen[sub]; ok {
			continue
		}
		seen[sub] = struct{}{}

		results = append(results, core.Result{
			Scanner:  "subdomain_subfinder",
			Category: "discovery",
			Target:   domain,
			Data: map[string]string{
				"method":    "subfinder",
				"subdomain": sub,
			},
			Severity:  "info",
			Timestamp: time.Now(),
		})
	}

	if err := cmd.Wait(); err != nil {
		return nil, err
	}

	return results, nil
}
