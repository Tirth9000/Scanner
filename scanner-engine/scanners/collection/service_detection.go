package collection

import (
	"context"
	"strings"
	"strconv"
	"time"
	"os/exec"
	"encoding/xml"
	"fmt"

	"scanner-platform/scanner-engine/core"
)

type ServiceDetectionScanner struct {}

func NewServiceDetectionScanner() *ServiceDetectionScanner {
	return &ServiceDetectionScanner{}
}

func (s *ServiceDetectionScanner) Name() string {
	return "Service Detection Scanner"
}

func (s *ServiceDetectionScanner) Category() string {
	return "Collection"
}

func (s *ServiceDetectionScanner) RunCollectionScanner(
	ctx context.Context,
	subdomains core.Result,
	domain string,
) (core.Result, error) {
	// null := core.Result{}

	for _, item := range subdomains.Data.([]interface{}) {

		m := item.(map[string]any)
		host := m["subdomain"].(string)

		ports, ok := m["port_collection"].([]core.PortData)
		if !ok || len(ports) == 0 {
			continue
		}

		// Build port list: "22,80,443"
		var portList []string
		for _, p := range ports {
			portList = append(portList, strconv.Itoa(p.Port))
		}

		cmd := exec.CommandContext(
			ctx,
			"nmap",
			"-p", strings.Join(portList, ","),
			"-sV",
			"-T4",
			"-Pn",
			"--max-retries", "1",
			"--host-timeout", "15s",
			"-oX", "-", // XML output
			host,
		)

		out, err := cmd.Output()
		if err != nil {
			fmt.Println("nmap error:", err)
			continue
		}

		// Parse XML
		var result core.NmapRun
		if err := xml.Unmarshal(out, &result); err != nil {
			fmt.Println("xml parse error:", err)
			continue
		}

		// Map port → service
		serviceMap := make(map[int]core.Port)

		for _, h := range result.Hosts {
			for _, p := range h.Ports {
				if p.State.State == "open" {
					serviceMap[p.PortID] = p
				}
			}
		}

		// Attach to your existing port_collection
		for i := range ports {
			if svc, ok := serviceMap[ports[i].Port]; ok {

				ports[i].Service = svc.Service.Name

				// Optional: version info
				// version := strings.TrimSpace(
				// 	svc.Service.Product + " " + svc.Service.Version,
				// )

				if svc.Service.Product != "" {
					ports[i].Product = svc.Service.Product
				}

				if svc.Service.Version != "" {
					ports[i].Version = svc.Service.Version
				}
			}
		}

		m["port_collection"] = ports
	}

	return core.Result{
		Scanner:   s.Name(),
		Category:  s.Category(),
		Target:    domain,
		Data:      subdomains.Data,
		Timestamp: time.Now(),
	}, nil
}
