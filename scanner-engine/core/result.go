package core

import "time"

type Result struct {
	Scanner   string
	Category  string
	Target    string
	Data      any
	Severity  string
	Timestamp time.Time
}

type HTTPScanData struct {
	Subdomain  string `json:"subdomain"`
	URL        string `json:"url"`
	StatusCode int    `json:"status_code"`
	Scheme     string `json:"scheme"`

	Server       string   `json:"server"`
	Technologies []string `json:"technologies"`

	TLS struct {
		Enabled bool   `json:"enabled"`
		Version string `json:"version"`
		Issuer  string `json:"issuer"`
		Expired bool   `json:"expired"`
	} `json:"tls"`

	Headers struct {
		ContentSecurityPolicy bool `json:"content_security_policy"`
		StrictTransport       bool `json:"strict_transport_security"`
		XFrameOptions         bool `json:"x_frame_options"`
		XContentTypeOptions   bool `json:"x_content_type_options"`
	} `json:"headers"`

	Redirects struct {
		FinalURL      string `json:"final_url"`
		RedirectCount int    `json:"redirect_count"`
	} `json:"redirects"`

	Metadata struct {
		Title          string `json:"title"`
		ContentType    string `json:"content_type"`
		ContentLength  int  `json:"content_length"`
		ResponseTimeMs string  `json:"response_time_ms"`
	} `json:"metadata"`
}

type HTTPXOutput struct {
	URL         string            `json:"url"`
	FinalURL    string            `json:"final_url"`
	StatusCode  int               `json:"status_code"`
	Scheme      string            `json:"scheme"`
	Server      string            `json:"server"`
	Title       string            `json:"title"`
	ContentType string            `json:"content_type"`
	Tech        []string          `json:"tech"`
	Headers     map[string]string `json:"headers"`
	TLSData     struct {
		Version string `json:"version"`
		Issuer  string `json:"issuer"`
		Expired bool   `json:"expired"`
	} `json:"tls"`
	Time int64 `json:"time"`
}


type PortInfo struct {
	Port int  `json:"port"`
	TLS  bool `json:"tls"`
}

type HostInfo struct {
	Subdomain string     `json:"subdomain"`
	Ports     []PortInfo `json:"ports"`
}

type IPAggregate struct {
	IP    string     `json:"ip"`
	Ports []int      `json:"ports"`
	Hosts []HostInfo `json:"hosts"`
}

type NaabuOutput struct {
		Host     string `json:"host"`
		IP       string `json:"ip"`
		Port     int    `json:"port"`
		Protocol string `json:"protocol"`
		TLS      bool   `json:"tls"`
	}