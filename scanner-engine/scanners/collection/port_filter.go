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

type PortFilter struct{}

func NewPortFilter() *PortFilter {
	return &PortFilter{}
}

func (f *PortFilter) Name() string {
	return "ProtFilter"
}

func (f *PortFilter) Category() string {
	return "FilterScanner"
}

func (f *PortFilter) RunFilterScanner(
	ctx context.Context,
	results []core.Result,
	domain string,
) ([]core.Result, error) {

	var portFiltered []core.Result

	cmd := exec.CommandContext(
		ctx,
		"naabu",
		"-top-ports", "1000",
		"-scan-type", "connect",
		"-silent",
		"-json",
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
		sc := bufio.NewScanner(stderr)
		for sc.Scan() {
			fmt.Println("NAABU ERR:", sc.Text())
		}
	}()

	go func() {
		defer stdin.Close()

		for _, r := range results {
			switch data := r.Data.(type) {
			case map[string]string:
				if sub := data["subdomain"]; sub != "" {
					fmt.Fprintln(stdin, sub)
				}
			case core.HTTPScanData:
				if data.Subdomain != "" {
					fmt.Fprintln(stdin, data.Subdomain)
				}
			}
		}
	}()

	ipMap := make(map[string]*core.IPAggregate)

	ipPortsSeen := make(map[string]map[int]bool)
	hostPortsSeen := make(map[string]map[int]bool)

	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 1024), 1024*1024)

	for scanner.Scan() {
		var out core.NaabuOutput

		if err := json.Unmarshal(scanner.Bytes(), &out); err != nil {
			continue
		}

		ipAgg, exists := ipMap[out.IP]
		if !exists {
			ipAgg = &core.IPAggregate{
				IP: out.IP,
			}
			ipMap[out.IP] = ipAgg
			ipPortsSeen[out.IP] = make(map[int]bool)
		}

		if !ipPortsSeen[out.IP][out.Port] {
			ipAgg.Ports = append(ipAgg.Ports, out.Port)
			ipPortsSeen[out.IP][out.Port] = true
		}

		hostKey := out.IP + "|" + out.Host

		if _, ok := hostPortsSeen[hostKey]; !ok {
			hostPortsSeen[hostKey] = make(map[int]bool)
			ipAgg.Hosts = append(ipAgg.Hosts, core.HostInfo{
				Subdomain: out.Host,
				Ports:     []core.PortInfo{},
			})
		}

		var host *core.HostInfo
		for i := range ipAgg.Hosts {
			if ipAgg.Hosts[i].Subdomain == out.Host {
				host = &ipAgg.Hosts[i]
				break
			}
		}

		if !hostPortsSeen[hostKey][out.Port] {
			host.Ports = append(host.Ports, core.PortInfo{
				Port: out.Port,
				TLS:  out.TLS,
			})
			hostPortsSeen[hostKey][out.Port] = true
		}
	}

	for _, agg := range ipMap {
		portFiltered = append(portFiltered, core.Result{
			Scanner:  "naabu",
			Category: "port-scan",
			Target:   domain,
			Data: map[string]interface{}{
				"ip":    agg.IP,
				"ports": agg.Ports,
				"hosts": agg.Hosts,
			},
			Severity:  "info",
			Timestamp: time.Now(),
		})
	}

	return portFiltered, nil
}
