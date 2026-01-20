package filters

import (
	"bufio"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"scanner-platform/scanner-engine/core"
)

type DNSFilter struct{}

func NewDNSFilter() *DNSFilter {
	return &DNSFilter{}
}

func (f *DNSFilter) Name() string {
	return "DNSFilter"
}

func (f *DNSFilter) Category() string {
	return "FilterScanner"
}

func (f *DNSFilter) RunFilterScanner(ctx context.Context, results []core.Result, domain string) ([]core.Result, error) {
	cmd := exec.CommandContext(
		ctx,
		"dnsx",
		"-silent",
		"-l", "-",
	)

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, err
	}

	if err := cmd.Start(); err != nil {
		return nil, err
	}

	go func() {
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			fmt.Println("dnsx stderr:", scanner.Text())
		}
	}()

	go func() {
		defer stdin.Close()
		for _, sub := range results {
			sub.Data.(map[string]string)["subdomain"] = strings.TrimSpace(sub.Data.(map[string]string)["subdomain"] )
			if sub.Data.(map[string]string)["subdomain"]  != "" {
				fmt.Fprintln(stdin, sub.Data.(map[string]string)["subdomain"])
			}
		}
	}()

	var resolved []core.Result
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 1024), 1024*1024)

	for scanner.Scan() {
		resolved = append(resolved, core.Result{
			Scanner:  "DNSX Filter",
			Category: "discovery",
			Target:   domain,
			Data: map[string]string{
				"method":    "dnsx Filter",
				"subdomain": scanner.Text(),
			},
			Severity:  "info",
			Timestamp: time.Now(),
		})
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	if err := cmd.Wait(); err != nil {
		return nil, err
	}

	return resolved, nil
}
