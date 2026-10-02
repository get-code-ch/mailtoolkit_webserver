package main

import (
	"encoding/json"
	"errors"
	"os"
	"time"
)

type SMTPPorts struct {
	// MX receives mail from other servers (25), STARTTLS optional.
	MX string `json:"mx"`
	// Submission requires STARTTLS (587).
	Submission string `json:"submission"`
	// SMTPS is implicit TLS (465).
	SMTPS string `json:"smtps"`
}

type Configuration struct {
	// Hostname of the MX, used in the SMTP banner and Received headers.
	Hostname string `json:"hostname"`
	// Domains accepted by the MX, the first one is used for new addresses.
	Domains []string `json:"domains"`
	// Server is the listening IP address, empty for all.
	Server    string    `json:"server"`
	HTTPPort  string    `json:"http_port"`
	HTTPSPort string    `json:"https_port"`
	SMTPPorts SMTPPorts `json:"smtp_ports"`
	// Cert and Key enable HTTPS, STARTTLS and the submission ports.
	Cert string `json:"cert"`
	Key  string `json:"key"`
	// ACMEWebroot is served on the HTTP port under /.well-known/acme-challenge/
	// for certbot --webroot.
	ACMEWebroot    string   `json:"acme_webroot"`
	DataFolder     string   `json:"data_folder"`
	StaticFolder   string   `json:"static_folder"`
	Retention      Duration `json:"retention"`
	MaxMessageSize int64    `json:"max_message_size"`
	MaxMailboxes   int      `json:"max_mailboxes"`
	// IngestToken enables POST /ingest, for relays that cannot reach the
	// SMTP ports (Cloudflare Email Workers). The MTK_INGEST_TOKEN
	// environment variable overrides it, to keep the secret out of files.
	IngestToken string `json:"ingest_token"`
	// BehindCloudflare trusts the CF-Connecting-IP header sent by the
	// Cloudflare proxies for the visitor address.
	BehindCloudflare bool `json:"behind_cloudflare"`
}

// Duration reads a duration written as "24h" in JSON.
type Duration struct{ time.Duration }

func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	parsed, err := time.ParseDuration(s)
	d.Duration = parsed
	return err
}

func (c Configuration) tlsEnabled() bool {
	return c.Cert != "" && c.Key != ""
}

func getConfiguration(file string) (Configuration, error) {
	configuration := Configuration{
		HTTPPort:       "80",
		DataFolder:     "./data/",
		StaticFolder:   "./static/",
		Retention:      Duration{24 * time.Hour},
		MaxMessageSize: 25 << 20,
		MaxMailboxes:   1000,
	}
	buffer, err := os.ReadFile(file)
	if err != nil {
		return Configuration{}, err
	}
	if err := json.Unmarshal(buffer, &configuration); err != nil {
		return Configuration{}, err
	}

	if len(configuration.Domains) == 0 {
		return Configuration{}, errors.New("configuration: at least one domain is required")
	}
	if configuration.Retention.Duration <= 0 {
		return Configuration{}, errors.New("configuration: retention must be positive")
	}
	if token := os.Getenv("MTK_INGEST_TOKEN"); token != "" {
		configuration.IngestToken = token
	}
	if configuration.IngestToken != "" && len(configuration.IngestToken) < 32 {
		return Configuration{}, errors.New("configuration: ingest_token must be at least 32 characters")
	}
	if configuration.Hostname == "" {
		configuration.Hostname, _ = os.Hostname()
	}
	return configuration, nil
}
