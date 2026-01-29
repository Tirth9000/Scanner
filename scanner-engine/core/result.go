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
	IP         string `json:"ip"`
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
		ContentLength  int    `json:"content_length"`
		ResponseTimeMs string `json:"response_time_ms"`
	} `json:"metadata"`
}

type NaabuOutput struct {
	Host     string `json:"host"`
	IP       string `json:"ip"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
}

type TLSDetails struct {
	Enabled    bool      `json:"enabled"`
	Version    string    `json:"version,omitempty"`
	Cipher     string    `json:"cipher,omitempty"`
	ALPN       string    `json:"alpn,omitempty"`
	Issuer     string    `json:"issuer,omitempty"`
	NotBefore  time.Time `json:"not_before,omitempty"`
	NotAfter   time.Time `json:"not_after,omitempty"`
	Expired    bool      `json:"expired"`
	SelfSigned bool      `json:"self_signed"`
	WeakTLS    bool      `json:"weak_tls"`
}

type TLSXOutput struct {
	Host       string    `json:"host"`
	Port       int       `json:"port"`
	TLS        bool      `json:"tls"`
	Version    string    `json:"version"`
	Cipher     string    `json:"cipher"`
	ALPN       string    `json:"alpn"`
	Issuer     string    `json:"issuer"`
	NotBefore  time.Time `json:"not_before"`
	NotAfter   time.Time `json:"not_after"`
	Expired    bool      `json:"expired"`
	SelfSigned bool      `json:"self_signed"`
	WeakTLS    bool      `json:"weak_tls"`
}

type PortData struct {
	Port       int         `json:"port"`
	Protocol   string      `json:"protocol"`
	TLSDetails *TLSDetails `json:"tls_details,omitempty"`
}
