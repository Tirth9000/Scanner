package collection

import (
	"context"
	"encoding/xml"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"time"

	"scanner-platform/scanner-engine/core"
)

type ServiceDetectionScanner struct{}

func NewServiceDetectionScanner() *ServiceDetectionScanner {
	return &ServiceDetectionScanner{}
}

func (s *ServiceDetectionScanner) Name() string {
	return "Service Detection Scanner"
}

func (s *ServiceDetectionScanner) Category() string {
	return "Collection"
}

func resolveIP(host string) string {
	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		return ""
	}
	return ips[0].String()
}

func (s *ServiceDetectionScanner) RunCollectionScanner(
	ctx context.Context,
	subdomains core.Result,
	domain string,
) (core.Result, error) {

	type groupKey string
	grouped := make(map[groupKey][]string)

	data, ok := subdomains.Data.([]interface{})
	if !ok {
		return subdomains, fmt.Errorf("invalid data format")
	}

	// ✅ STEP 1: Normalize + Group
	for _, item := range data {

		m, ok := item.(map[string]any)
		if !ok {
			continue
		}

		sub, _ := m["subdomain"].(string)
		if sub == "" {
			continue
		}

		rawPorts, exists := m["port_collection"]
		if !exists || rawPorts == nil {
			continue // 🔥 avoid panic
		}

		var ports []core.PortData

		// ✅ HANDLE BOTH TYPES
		switch v := rawPorts.(type) {

		case []core.PortData:
			ports = v

		case []interface{}:
			for _, p := range v {
				pm, ok := p.(map[string]interface{})
				if !ok {
					continue
				}

				portFloat, _ := pm["port"].(float64)

				ports = append(ports, core.PortData{
					Port: int(portFloat),
				})
			}

		default:
			continue
		}

		if len(ports) == 0 {
			continue
		}

		// build port list
		var portList []string
		for _, p := range ports {
			portList = append(portList, fmt.Sprintf("%d", p.Port))
		}

		key := groupKey(strings.Join(portList, ","))

		grouped[key] = append(grouped[key], sub)

		// 🔥 store normalized ports back
		m["port_collection"] = ports
	}

	// ✅ STEP 2: Run Nmap per group
	for key, hosts := range grouped {

		portList := string(key)

		fmt.Println("Running Nmap:", hosts, "ports:", portList)

		cmd := exec.CommandContext(
			ctx,
			"nmap",
			"-p", portList,
			"-sV",
			"--min-rate", "1000",
			"-T4",
			"-Pn",
			"--max-retries", "3",
			"--script", "banner",
			"-oX", "-",
		)

		cmd.Args = append(cmd.Args, hosts...)

		out, err := cmd.CombinedOutput()
		if err != nil {
			fmt.Println("nmap error:", err)
			fmt.Println(string(out))
			continue
		}

		var result core.NmapRun
		if err := xml.Unmarshal(out, &result); err != nil {
			fmt.Println("xml parse error:", err)
			continue
		}

		// ✅ STEP 3: Map results back
		for _, h := range result.Hosts {

			var host string

			if len(h.Hostnames) > 0 {
				host = h.Hostnames[0].Name
			} else if len(h.Addresses) > 0 {
				host = h.Addresses[0].Addr
			} else {
				continue
			}

			for _, item := range data {

				m := item.(map[string]any)
				sub, _ := m["subdomain"].(string)

				if sub != host {
					continue
				}

				ports, ok := m["port_collection"].([]core.PortData)
				if !ok {
					continue
				}

				for i := range ports {
					for _, p := range h.Ports {

						if p.PortID == ports[i].Port &&
							p.State.State == "open" {

							ports[i].Service = p.Service.Name
							ports[i].Product = p.Service.Product
							ports[i].Version = p.Service.Version
						}
					}
				}

				m["port_collection"] = ports
			}
		}
	}

	return core.Result{
		Scanner:   s.Name(),
		Category:  s.Category(),
		Target:    domain,
		Data:      data,
		Timestamp: time.Now(),
	}, nil
}