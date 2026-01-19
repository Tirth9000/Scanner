package collection

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"time"

	"scanner-platform/scanner-engine/core"
)

type HTTPXFilterOutput struct{}

func NewHTTPXFilterOutput() *HTTPXFilterOutput {
	return &HTTPXFilterOutput{}
}

func (f *HTTPXFilterOutput) Name() string {
	return "HTTPXFilter Details"
}

func (f *HTTPXFilterOutput) Category() string {
	return "HTTPX FilterScanner"
}

func extractHost(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	return u.Hostname()
}

func (f *HTTPXFilterOutput) RunCollectionScanner(
	ctx context.Context,
	subdomains []core.Result,
	target string,
) ([]core.Result, error) {

	cmd := exec.CommandContext(
		ctx,
		"httpx",
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
		defer stdin.Close()

		for _, r := range subdomains {
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

	go func() {
		io.Copy(os.Stderr, stderr)
	}()

	var httpData []core.Result

	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 1024), 1024*1024)

	for scanner.Scan() {
		var hx struct {
			URL           string   `json:"url"`
			Input         string   `json:"input"`
			Scheme        string   `json:"scheme"`
			StatusCode    int      `json:"status_code"`
			Title         string   `json:"title"`
			ContentType   string   `json:"content_type"`
			ContentLength int      `json:"content_length"`
			Time          string   `json:"time"`
			Host          string   `json:"host"`
			HostIP        string   `json:"host_ip"`
			Port          string   `json:"port"`
			Tech          []string `json:"tech"`
			Failed        bool     `json:"failed"`
		}

		if err := json.Unmarshal(scanner.Bytes(), &hx); err != nil {
			continue
		}

		// httpx already filters live hosts, but be defensive
		if hx.URL == "" || hx.Failed {
			continue
		}

		data := core.HTTPScanData{
			Subdomain:    hx.Host,
			URL:          hx.URL,
			StatusCode:   hx.StatusCode,
			Scheme:       hx.Scheme,
			Server:       "", // httpx does not always emit this
			Technologies: hx.Tech,
		}

		data.TLS.Enabled = hx.Scheme == "https"

		data.Metadata.Title = hx.Title
		data.Metadata.ContentType = hx.ContentType
		data.Metadata.ContentLength = hx.ContentLength
		data.Metadata.ResponseTimeMs = hx.Time

		httpData = append(httpData, core.Result{
			Scanner:   f.Name(),
			Category:  f.Category(),
			Target:    target,
			Data:      map[string]any{
				"subdomain": hx.Host,
				"http_data" : data,
			},
			Severity:  "info",
			Timestamp: time.Now(),
		})
	}

	if err := scanner.Err(); err != nil {
		return httpData, err
	}

	if err := cmd.Wait(); err != nil {
		return httpData, err
	}
	fmt.Printf("%+v\n", httpData[0])

	return httpData, nil
}
