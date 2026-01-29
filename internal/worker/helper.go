package worker

import (
	"bytes"
	"net/http"
	"encoding/json"
)

func send_webhook_notification(payload map[string]string) (any, error) {
	url := "http://0.0.0.0:8000/webhooks/scanner"

	jsonData, err := json.Marshal(payload)
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