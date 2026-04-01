package worker

import (
	"bytes"
	"encoding/json"
	"net/http"
	"scanner-platform/internal/models"
)

func send_webhook_notification(payload models.ScanNotification) (any, error) {
	url := "http://scanner-backend:8000/webhooks/scan/notification"

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

func send_scan_result_webhook(payload models.ScanResult) (any, error) {
	url := "http://scanner-backend:8000/webhooks/scan/result"

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


func send_fix_result_webhook(payload models.FixScanResult) (any, error) {
	url := "http://scanner-backend:8000/api/fix/result"

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
