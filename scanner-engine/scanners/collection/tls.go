package collection

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
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
		443:  true,
		8443: true,
		9443: true,
		993:  true,
		995:  true,
		465:  true,
		587:  true,
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
	subdomains core.Result,
	domain string,
) (core.Result, error) {

	null := core.Result{}

	cmd := exec.CommandContext(
		ctx,
		"tlsx",
		"-silent",
		"-json",
		"-jarm",
		"-tls-version",
		"-cipher",
	)

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return null, err
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return null, err
	}

	if err := cmd.Start(); err != nil {
		return null, err
	}

	go func() {
		defer stdin.Close()

		for _, item := range subdomains.Data.([]interface{}) {
			m := item.(map[string]any)
			// fmt.Println(m)

			host := m["subdomain"].(string)
			ports := m["port_collection"]

			if ports == nil {
				continue
			}

			for _, p := range ports.([]core.PortData) {
				fmt.Fprintf(stdin, "%s:%d\n", host, p.Port)
				// if p.Port == 443 || p.Port == 8443 || p.Port == 993 || p.Port == 465 {
				// }
			}
		}
	}()

	scanner := bufio.NewScanner(stdout)

	for scanner.Scan() {

		var out core.TLSXOutput
		if err := json.Unmarshal(scanner.Bytes(), &out); err != nil {
			continue
		}

		host := out.Host
		portStr := out.Port
		port, _ := strconv.Atoi(portStr)

		notAfter, err := time.Parse(time.RFC3339, out.NotAfter)

		expired := false
		if err == nil {
			expired = time.Now().After(notAfter)
		}

		tlsData := &core.TLSData{
			Enabled:     out.ProbeStatus,
			Version:     out.TLSVersion,
			Cipher:      out.Cipher,
			Issuer:      out.IssuerDN,
			Subject:     out.SubjectDN,
			NotBefore:   out.NotBefore,
			NotAfter:    out.NotAfter,
			Expired:     expired,
			SelfSigned:  out.SubjectCN == out.IssuerCN,
			Wildcard:    out.WildcardCertificate,
			SAN:         out.SubjectAN,
			JARM:        out.JARMHash,
			Fingerprint: out.FingerprintHash.SHA256,
		}
		// fmt.Println(tlsData)

		// Attach TLS to correct port
		for _, item := range subdomains.Data.([]interface{}) {
			m := item.(map[string]any)

			if m["subdomain"] != host {
				continue
			}

			ports := m["port_collection"].([]core.PortData)

			for i := range ports {
				if ports[i].Port == port {
					ports[i].TLS = tlsData
				}
			}

			m["port_collection"] = ports
		}
	}
	tlsResult := core.Result{
		Scanner:   f.Name(),
		Category:  f.Category(),
		Target:    domain,
		Data:      subdomains.Data,
		Timestamp: time.Now(),
	}

	return tlsResult, nil
}
