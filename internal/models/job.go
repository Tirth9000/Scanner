package models

import "time"

type ScanJob struct {
	ScanID string `json:"scan_id"`
	Target string `json:"target"`
}

type ScanNotification struct {
	ScanID string `json:"scan_id"`
	Target string `json:"target"`
	Event  string `json:"event"`
	Status string `json:"status"`
}

type ScanResult struct {
	ScanID    string    `json:"scan_id"`
	Target    string    `json:"target"`
	Data      any       `json:"data"`
	Timestamp time.Time `json:"timestamp"`
}
