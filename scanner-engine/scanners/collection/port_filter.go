package collection

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"

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

func (f *PortFilter) RunCollectionScanner(
	ctx context.Context,
	results []core.Result,
	domain string,
) ([]core.Result, error) {

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
			data, ok := r.Data.(map[string]any)
			if !ok {
				continue
			}

			sub := data["subdomain"].(string)

			if sub == "" {
				continue
			}

			fmt.Fprintln(stdin, sub)
		}
	}()

	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 1024), 1024*1024)

	portMap := make(map[string][]core.PortData)

	for scanner.Scan() {
		var out core.NaabuOutput

		if err := json.Unmarshal(scanner.Bytes(), &out); err != nil {
			return nil, err
		}

		portMap[out.Host] = append(portMap[out.Host], core.PortData{
			Port:     out.Port,
			Protocol: out.Protocol,
		})

	}

	for _, r := range results {
		data, ok := r.Data.(map[string]any)
		if !ok {
			continue
		}

		sub, ok := data["subdomain"].(string)
		if !ok || sub == "" {
			continue
		}

		ports, exists := portMap[sub]
		if !exists {
			continue
		}

		data["ports"] = ports
	}

	return results, nil
}
