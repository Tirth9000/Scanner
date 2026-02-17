package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
)

type Result struct {
	Name string
	Data any
}

func send_webhook_notification(payload map[string]any) (any, error) {
	url := "http://0.0.0.0:8000/webhooks/scan/result"

	// jsonData, err := json.Marshal(payload)
	jsonData, err := json.MarshalIndent(payload, "", "  ")
	fmt.Println(string(jsonData))
	
	if err != nil {
		return nil, err
	}
	res, err := http.Post(
		url,
		"application/json",
		bytes.NewBuffer(jsonData),
	)

	if err != nil {
		return nil, err
	}

	defer res.Body.Close()

	return res.Status, nil
}

func main() {
	finalResults := []Result{}

	data := []map[string]string{}

	for i := 0; i < 5; i++ {
		data = append(data, map[string]string{
			"subdomain": fmt.Sprintf("subdomain%d.example.com", i),
			"port":      fmt.Sprint(i),
			"tls":       fmt.Sprintf("TLS%d", i),
		})
	}

	fmt.Println("Collected Data:", data)

	finalResults = append(finalResults, Result{
		Name: "subdomain_scanner",
		Data: data,
	})

	fmt.Println("Final Results:", finalResults)
	testData := finalResults[0].Data.([]map[string]string)

	for _, entry := range testData {
		fmt.Println("Subdomain:", entry["subdomain"])
	}

	collection_payload := map[string]any{
		"scan_id": "sample-scan-id",
		"target":  "example.com",
		"data":    finalResults,
	}
	collection_res, err := send_webhook_notification(collection_payload)
	if err != nil {
		fmt.Printf("Failed to send webhook notification: %v", err)
	}

	fmt.Println("Webhook Response:", collection_res)
}
