package discovery

import (
	"context"
	"net"
	"scanner-platform/scanner/core"
	"time"
)

type DNSScanner struct{}

func NewDNSScanner() *DNSScanner {
	return &DNSScanner{}
}

func (d *DNSScanner) Name() string {
	return "dns_scanner"
}

func (d *DNSScanner) Category() string {
	return "discovery"
}

func (d *DNSScanner) Run(
	ctx context.Context,
	target string,
) ([]core.Result, error) {

	var results []core.Result

	ips, err := net.LookupIP(target)
	if err != nil {
		return nil, err
	}

	for _, ip := range ips {
		recordType := "AAAA"
		if ip.To4() != nil {
			recordType = "A"
		}

		results = append(results, core.Result{
			Scanner:  d.Name(),
			Category: d.Category(),
			Target:   target,
			Data: map[string]string{
				"ip":     ip.String(),
				"record": recordType,
			},
			Severity:  "info",
			Timestamp: time.Now(),
		})
	}

	return results, nil
}
