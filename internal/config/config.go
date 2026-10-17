// Package config loads and validates Blacknet's YAML bootstrap configuration.
//
// The YAML file covers bootstrap-level settings that require a restart
// (listen addresses, data directory, logging). Runtime-editable settings
// (blocking mode, upstreams, rules, retention, ...) live in SQLite and are
// managed through the API.
package config

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Config is the root bootstrap configuration.
type Config struct {
	DataDir  string     `yaml:"data_dir"`
	LogLevel string     `yaml:"log_level"`
	DNS      DNSConfig  `yaml:"dns"`
	Web      WebConfig  `yaml:"web"`
	Update   UpdateConf `yaml:"updates"`
	APIToken string     `yaml:"api_token"` // bootstrap token for CLI access; stored in api.token file if empty
}

// DNSConfig controls the DNS listener.
type DNSConfig struct {
	Listen       []string `yaml:"listen"`        // ["ip:port", ...]; port defaults to 53
	TrustedCIDRs []string `yaml:"trusted_cidrs"` // allowed client networks
}

// WebConfig controls the dashboard/API listener.
type WebConfig struct {
	Listen string `yaml:"listen"` // ip:port; localhost-only unless set otherwise
}

// UpdateConf controls optional external checks (off by default).
type UpdateConf struct {
	CheckEnabled bool `yaml:"check_enabled"`
}

// Default returns a config with safe defaults: DNS on the machine's LAN
// address is selected at runtime; the web UI binds to all interfaces is NOT
// the default - it binds to 0.0.0.0 so LAN devices can reach the dashboard,
// protected by authentication. Trusted CIDRs default to common private ranges.
func Default() *Config {
	c := &Config{
		DataDir:  "data",
		LogLevel: "info",
	}
	c.DNS.Listen = []string{"0.0.0.0:53", "[::]:53"}
	c.DNS.TrustedCIDRs = []string{
		"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
		"127.0.0.0/8", "::1/128", "fe80::/10", "fc00::/7",
		"169.254.0.0/16",
	}
	c.Web.Listen = "0.0.0.0:8080"
	return c
}

// Path resolution: if BLACKNET_CONFIG is set it wins; otherwise config.yaml
// next to the working directory is used, falling back to Default().
func Load(path string) (*Config, error) {
	if path == "" {
		path = os.Getenv("BLACKNET_CONFIG")
	}
	if path == "" {
		path = "config.yaml"
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) && path == "config.yaml" {
			c := Default()
			return c, nil
		}
		return nil, fmt.Errorf("read config: %w", err)
	}
	c := Default()
	if err := yaml.Unmarshal(data, c); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config %s: %w", path, err)
	}
	return c, nil
}

// Validate checks the config; returns the first problem found.
func (c *Config) Validate() error {
	if c.DataDir == "" {
		return fmt.Errorf("data_dir must not be empty")
	}
	if len(c.DNS.Listen) == 0 {
		return fmt.Errorf("dns.listen must contain at least one address")
	}
	for _, a := range c.DNS.Listen {
		host, port, err := net.SplitHostPort(a)
		if err != nil {
			return fmt.Errorf("dns.listen %q: %w", a, err)
		}
		if host == "" {
			return fmt.Errorf("dns.listen %q: empty host", a)
		}
		if _, err := netip.ParseAddr(host); err != nil {
			return fmt.Errorf("dns.listen %q: invalid IP: %w", a, err)
		}
		if p := portNum(port); p < 1 || p > 65535 {
			return fmt.Errorf("dns.listen %q: invalid port", a)
		}
	}
	if len(c.DNS.TrustedCIDRs) == 0 {
		return fmt.Errorf("dns.trusted_cidrs must not be empty (refuse to run an open resolver)")
	}
	for _, cidr := range c.DNS.TrustedCIDRs {
		if _, err := netip.ParsePrefix(cidr); err != nil {
			return fmt.Errorf("dns.trusted_cidrs %q: %w", cidr, err)
		}
	}
	if _, _, err := net.SplitHostPort(c.Web.Listen); err != nil {
		return fmt.Errorf("web.listen %q: %w", c.Web.Listen, err)
	}
	switch c.LogLevel {
	case "", "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("log_level %q invalid", c.LogLevel)
	}
	return nil
}

func portNum(s string) int {
	n := 0
	for _, ch := range s {
		if ch < '0' || ch > '9' {
			return -1
		}
		n = n*10 + int(ch-'0')
	}
	return n
}

// TrustedPrefixes parses the configured CIDR allowlist.
func (c *Config) TrustedPrefixes() ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, s := range c.DNS.TrustedCIDRs {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, err
		}
		out = append(out, p.Masked())
	}
	return out, nil
}

// DBPath returns the SQLite file location inside DataDir.
func (c *Config) DBPath() string { return filepath.Join(c.DataDir, "blacknet.db") }

// TokenPath returns where the generated API token is persisted.
func (c *Config) TokenPath() string { return filepath.Join(c.DataDir, "api.token") }

// WriteExample writes a commented example config to path.
func WriteExample(path string) error {
	example := `# Blacknet bootstrap configuration.
# Runtime settings (upstreams, rules, blocklists, blocking mode) live in the
# SQLite database and are managed through the API/dashboard.

data_dir: data
log_level: info

dns:
  # Addresses the DNS server binds to. Prefer the host's LAN address; the
  # defaults below bind all interfaces but untrusted clients are refused by
  # trusted_cidrs below. Change to the LAN IP for a tighter bind.
  listen:
    - "0.0.0.0:53"
    - "[::]:53"
  # Client networks allowed to query this resolver. Defaults cover RFC1918,
  # loopback, link-local and ULA. Never add 0.0.0.0/0.
  trusted_cidrs:
    - "10.0.0.0/8"
    - "172.16.0.0/12"
    - "192.168.0.0/16"
    - "127.0.0.0/8"
    - "::1/128"
    - "fe80::/10"
    - "fc00::/7"
    - "169.254.0.0/16"

web:
  # Dashboard and API bind address.
  listen: "0.0.0.0:8080"

updates:
  # Optional external version check. Disabled by default; no telemetry is sent.
  check_enabled: false
`
	return os.WriteFile(path, []byte(example), 0o600)
}
