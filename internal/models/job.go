package models

import "time"

type ScanJob struct {
	ScanID string `json:"scan_id"`
	Target string `json:"target"`
}

type FixScanJob struct {
	ScanID  string `json:"scan_id"`
	Domain  string `json:"domain"`
	FixType string `json:"fix_type"` // e.g., "port", "vulnerability", etc.
	Data    any    `json:"data"`     // Additional data needed for the fix, e.g., port number
}

type FixScanResult struct {
	ScanID  string `json:"scan_id"`
	Domain  string `json:"domain"`
	FixType string `json:"fix_type"`
	Result  any    `json:"result"` // Result of the fix operation, e.g., success/failure or details
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
