package collection

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"time"

	"scanner-platform/scanner-engine/core"
)

type DNSDataOutput struct{}

func NewDNSDataOutput() *DNSDataOutput {
	return &DNSDataOutput{}
}

func (f *DNSDataOutput) Name() string {
	return "DNS Data Collection"
}

func (f *DNSDataOutput) Category() string {
	return "DNS Data Collection"
}

func (f *DNSDataOutput) RunCollectionScanner(
	ctx context.Context,
	subdomains []core.Result,
	target string,
) ([]core.Result, error) {
	cmd := exec.Command(
		"dnsx",
		"-json",
		"-a",
		"-aaaa",
		"-cname",
		"-mx",
		"-ns",
		"-txt",
		"-resp",
		"-silent",
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
		defer stdin.Close()

		for _, r := range subdomains {
			data, ok := r.Data.(map[string]any)
			if !ok {
				continue
			}

			sub := data["subdomain"]
			if sub == "" {
				continue
			}

			fmt.Fprintln(stdin, sub)
		}
	}()

	go func() {
		io.Copy(os.Stderr, stderr)
	}()

	var DnsData []core.Result

	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 1024), 1024*1024)

	for scanner.Scan() {
		dd := core.DNSXResult{}

		if err := json.Unmarshal(scanner.Bytes(), &dd); err != nil {
			continue
		}

		DnsData = append(DnsData, core.Result{
			Scanner:   f.Name(),
			Category:  f.Category(),
			Target:    dd.Host,
			Data:      dd,
			Timestamp: time.Now(),
		})

	}

	return DnsData, nil
}
