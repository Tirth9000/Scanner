package collection

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"strconv"
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

func isTLSCandidate(port int) bool {
	tlsPorts := map[int]bool{
		443: true,
		8443: true,
		9443: true,
		993: true,
		995: true,
		465: true,
		587: true,
	}
	return tlsPorts[port]
}

func detectWildcard(sans []string) bool {
	for _, s := range sans {
		if strings.HasPrefix(s, "*.") {
			return true
		}
	}
	return false
}

func (f *TLSDataCollection) RunCollectionScanner(
	ctx context.Context,
	results []core.Result,
	domain string,
) ([]core.Result, error) {

	cmd := exec.CommandContext(ctx,
		"tlsx",
		"-json",
		"-silent",
		"-san",
		"-cn",
		"-issuer",
		"-fingerprint",
		"-version",
		"-cipher",
		"-expiry",
	)

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

	// Feed TLS candidate ports
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
				// Scan common TLS ports only
				if isTLSCandidate(p.Port) {
					fmt.Fprintf(stdin, "%s:%d\n", subdomain, p.Port)
				}
			}
		}
	}()

	// Collect TLS results
	tlsMap := make(map[string]map[int]core.TLSXOutput)

	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 1024), 1024*1024)

	for scanner.Scan() {
		var out core.TLSXOutput
		if err := json.Unmarshal(scanner.Bytes(), &out); err != nil {
			continue
		}

		portInt, err := strconv.Atoi(out.Port)
		if err != nil {
			continue
		}

		if _, ok := tlsMap[out.Host]; !ok {
			tlsMap[out.Host] = make(map[int]core.TLSXOutput)
		}

		tlsMap[out.Host][portInt] = out
	}

	// Attach TLS to ports
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

				if tlsOut, ok := hostTLS[ports[j].Port]; ok {

					tlsInfo := &core.TLSInfo{
						Version:   tlsOut.TLSVersion,
						Cipher:    tlsOut.Cipher,
						ValidFrom: tlsOut.NotBefore,
						ValidTo:   tlsOut.NotAfter,
						Expired:   time.Now().After(tlsOut.NotAfter),
						IssuerCN:  tlsOut.IssuerCN,
						SubjectCN: tlsOut.SubjectCN,
						SAN:       tlsOut.SubjectAN,
						SHA256Fingerprint: tlsOut.Fingerprint.SHA256,
						Wildcard:  detectWildcard(tlsOut.SubjectAN),
					}

					ports[j].TLS = tlsInfo
				}
			}
		}

		data["ports"] = ports
		results[i].Data = data
	}

	return results, nil
}