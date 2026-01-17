package filters


import (
	"context"
	"fmt"
	"os/exec"
	"bufio"
	"encoding/json"
	"time"

	"scanner-platform/scanner-engine/core"
)


type HTTPFilter struct {}

func  NewHTTPFilter() *HTTPFilter {
	return &HTTPFilter{}
}

func (f *HTTPFilter) Name() string {
	return "HTTPFilter"
}

func (f *HTTPFilter) Category() string {
	return "FilterScanner"
}

func (f *HTTPFilter) RunFilterScanner(
	ctx context.Context,
	results []core.Result,
	domain string,
) ([]core.Result, error) {

	cmd := exec.CommandContext(ctx, "httpx", "-silent", "-json")

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

	// Feed subdomains safely
	go func() {
		defer stdin.Close()
		for _, r := range results {
			data, ok := r.Data.(map[string]string)
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

	var live []core.Result
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 1024), 1024*1024)

	for scanner.Scan() {
		var hx struct {
			URL        string `json:"url"`
			StatusCode int    `json:"status_code"`
		}

		if err := json.Unmarshal(scanner.Bytes(), &hx); err != nil {
			continue
		}

		// httpx already filters liveness — this is just safety
		if hx.URL != "" && (hx.StatusCode == 200 || hx.StatusCode == 301 || hx.StatusCode == 302) {

			live = append(live, core.Result{
				Scanner:  f.Name(),
				Category: f.Category(),
				Target:   domain,
				Data: map[string]string{
					"subdomain": hx.URL,
				},
				Severity:  "info",
				Timestamp: time.Now(),
			})
		}
	}

	if err := cmd.Wait(); err != nil {
		return live, err
	}

	return live, nil
}