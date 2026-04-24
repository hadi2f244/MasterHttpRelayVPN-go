// Package config loads and validates the proxy configuration.
package config

import (
	"encoding/json"
	"fmt"
	"os"
)

// Config holds all runtime settings.
type Config struct {
	Mode       string `json:"mode"`        // "apps_script" (primary)
	GoogleIP   string `json:"google_ip"`   // e.g. "216.239.38.120"
	FrontDomain string `json:"front_domain"` // SNI for outbound TLS
	ScriptID   string `json:"script_id"`   // single Apps Script deployment ID
	ScriptIDs  []string `json:"script_ids"` // multiple IDs for round-robin
	AuthKey    string `json:"auth_key"`
	ListenHost string `json:"listen_host"`
	ListenPort int    `json:"listen_port"`
	Socks5Enabled bool   `json:"socks5_enabled"`
	Socks5Host  string `json:"socks5_host"`
	Socks5Port  int    `json:"socks5_port"`
	LogLevel    string `json:"log_level"`
	VerifySSL   bool   `json:"verify_ssl"`

	// Worker / Cloud Run / custom domain settings (modes 1-3)
	WorkerHost   string `json:"worker_host"`
	WorkerPath   string `json:"worker_path"`
	CustomDomain string `json:"custom_domain"`

	// Advanced routing
	Hosts              map[string]string `json:"hosts"`
	DirectGoogleExclude []string          `json:"direct_google_exclude"`
	DirectGoogleAllow   []string          `json:"direct_google_allow"`
}

// Load reads config from path, applies env-var and CLI overrides, validates.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("open config: %w", err)
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	// Env-var overrides
	if v := os.Getenv("DFT_AUTH_KEY"); v != "" {
		cfg.AuthKey = v
	}
	if v := os.Getenv("DFT_SCRIPT_ID"); v != "" {
		cfg.ScriptID = v
	}

	// Defaults
	if cfg.Mode == "" {
		cfg.Mode = "apps_script"
	}
	if cfg.GoogleIP == "" {
		cfg.GoogleIP = "216.239.38.120"
	}
	if cfg.FrontDomain == "" {
		cfg.FrontDomain = "www.google.com"
	}
	if cfg.ListenHost == "" {
		cfg.ListenHost = "127.0.0.1"
	}
	if cfg.ListenPort == 0 {
		cfg.ListenPort = 8085
	}
	if cfg.Socks5Host == "" {
		cfg.Socks5Host = cfg.ListenHost
	}
	if cfg.Socks5Port == 0 {
		cfg.Socks5Port = 1080
	}
	if cfg.LogLevel == "" {
		cfg.LogLevel = "INFO"
	}
	if !cfg.VerifySSL {
		// keep whatever was set
	} else {
		cfg.VerifySSL = true
	}

	if err := validate(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// ScriptIDList returns the effective list of script IDs.
func (c *Config) ScriptIDList() []string {
	if len(c.ScriptIDs) > 0 {
		return c.ScriptIDs
	}
	if c.ScriptID != "" {
		return []string{c.ScriptID}
	}
	return nil
}

func validate(cfg *Config) error {
	if cfg.AuthKey == "" {
		return fmt.Errorf("missing required config key: auth_key")
	}
	switch cfg.Mode {
	case "apps_script":
		ids := cfg.ScriptIDList()
		if len(ids) == 0 || (len(ids) == 1 && ids[0] == "YOUR_APPS_SCRIPT_DEPLOYMENT_ID") {
			return fmt.Errorf("apps_script mode requires script_id in config")
		}
	case "custom_domain":
		if cfg.CustomDomain == "" {
			return fmt.Errorf("custom_domain mode requires custom_domain in config")
		}
	case "domain_fronting":
		if cfg.FrontDomain == "" || cfg.WorkerHost == "" {
			return fmt.Errorf("domain_fronting mode requires front_domain and worker_host")
		}
	case "google_fronting":
		if cfg.WorkerHost == "" {
			return fmt.Errorf("google_fronting mode requires worker_host (Cloud Run URL)")
		}
	}
	return nil
}
