package collection

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"time"

	"scanner-platform/scanner-engine/core"
)

type TLSDataCollection struct{}

func NewTLSDataCollection() *TLSDataCollection {
	return &TLSDataCollection{}
}

func (f *TLSDataCollection) Name() string {
	return "TLS Scanner"
}

func (f *TLSDataCollection) Category() string {
	return "Collection"
}

func (f *TLSDataCollection) RunFilterScanner(
	ctx context.Context,
	results []core.Result,
	domain string,
) ([]core.Result, error) {

	// Start tlsx CLI
	cmd := exec.CommandContext(ctx, "tlsx", "-json", "-silent")

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}

	if err := cmd.Start(); err != nil {
		return nil, err
	}

	// Feed all targets into tlsx
	go func() {
		defer stdin.Close()
		for _, r := range results {
			data, ok := r.Data.(map[string]any)
			if !ok {
				continue
			}
			subdomain, _ := data["subdomain"].(string)
			ports, ok := data["ports"].([]core.PortData)
			if !ok || subdomain == "" {
				continue
			}
			for _, p := range ports {
				// Only scan ports likely to have TLS
				if p.Port == 443 || p.Port == 993 || p.Port == 465 || p.Port == 587 {
					fmt.Fprintf(stdin, "%s:%d\n", subdomain, p.Port)
				}
			}
		}
	}()

	// Parse tlsx JSON output
	tlsMap := make(map[string]map[int]core.TLSXOutput)
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 1024), 1024*1024)

	for scanner.Scan() {
		var out core.TLSXOutput
		if err := json.Unmarshal(scanner.Bytes(), &out); err != nil {
			continue
		}
		if _, ok := tlsMap[out.Host]; !ok {
			tlsMap[out.Host] = make(map[int]core.TLSXOutput)
		}
		tlsMap[out.Host][out.Port] = out
	}

	// Attach TLS results to each port
	for i := range results {
		data, ok := results[i].Data.(map[string]any)
		if !ok {
			continue
		}

		subdomain, _ := data["subdomain"].(string)
		ports, ok := data["ports"].([]core.PortData)
		if !ok || subdomain == "" {
			continue
		}

		for j := range ports {
			if hostTLS, ok := tlsMap[subdomain]; ok {
				if tlsOut, ok := hostTLS[ports[j].Port]; ok && tlsOut.TLS {
					ports[j].TLSDetails = &core.TLSDetails{
						Enabled:    true,
						Version:    tlsOut.Version,
						Cipher:     tlsOut.Cipher,
						ALPN:       tlsOut.ALPN,
						Issuer:     tlsOut.Issuer,
						NotBefore:  tlsOut.NotBefore,
						NotAfter:   tlsOut.NotAfter,
						Expired:    time.Now().After(tlsOut.NotAfter),
						SelfSigned: tlsOut.SelfSigned,
						WeakTLS:    tlsOut.Version == "TLS1.0" || tlsOut.Version == "TLS1.1",
					}
				} else {
					ports[j].TLSDetails = nil
				}
			} else {
				ports[j].TLSDetails = nil
			}
		}

		data["ports"] = ports
		results[i].Data = data
	}

	return results, nil
}