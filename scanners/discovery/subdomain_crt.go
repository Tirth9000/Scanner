package discovery

import (
	"fmt"
    "context"
    "encoding/json"
    "net/http"
    "strings"
	"time"

    "scanner-platform/scanner/core"
)

type CrtCTScanner struct{}

func NewCrtCTScanner() *CrtCTScanner {
	return &CrtCTScanner{}
}

func (c *CrtCTScanner) Name() string {
    return "subdomain_crtsh"
}

func (c *CrtCTScanner) Category() string {
    return "discovery"
}

func (c *CrtCTScanner) Run(ctx context.Context, domain string) ([]core.Result, error) {
    url := "https://crt.sh/?q=%25." + domain + "&output=json"

    req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
    if err != nil {
        return nil, err
    }

    resp, err := http.DefaultClient.Do(req)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()

    var entries []map[string]interface{}
    if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
        return nil, err
    }

    seen := make(map[string]bool)
    var results []core.Result

    for _, entry := range entries {
        raw, ok := entry["name_value"].(string)
        if !ok {
            continue
        }

        names := strings.Split(raw, "\n")
        for _, sub := range names {
            sub = strings.TrimSpace(sub)

            if !IsValidSubdomain(sub, domain) {
                continue
            }
            
            if sub == "" || seen[sub] {
                continue
            }

            seen[sub] = true

            results = append(results, core.Result{
                Scanner:  c.Name(),
                Category: c.Category(),
                Target:   domain,
                Data: map[string]string{
                    "subdomain": sub,
                    "source":    "certificate_transparency",
                },
                Severity: "info",
				Timestamp: time.Now(),
            })
        }
    }
	fmt.Println(len(results))

    return results, nil
}