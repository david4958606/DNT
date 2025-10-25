package parser

import (
	"errors"
	"fmt"
	"io"
	"os"

	"gopkg.in/yaml.v3"
)

// Config represents the entire YAML playbook describing global options and
// per-module settings.
type Config struct {
	Version       int                 `yaml:"version"`
	Global        GlobalConfig        `yaml:"global"`
	Links         []string            `yaml:"links"`
	DNS           DNSConfig           `yaml:"dns"`
	IPDirect      IPDirectConfig      `yaml:"ip-direct"`
	TLS           TLSConfig           `yaml:"tls"`
	HTTP          HTTPConfig          `yaml:"http"`
	QUIC          QUICConfig          `yaml:"quic"`
	NetworkProbes NetworkProbesConfig `yaml:"network-probes"`
}

// GlobalConfig controls logging, concurrency, and other cross-module knobs.
type GlobalConfig struct {
	Logs               bool               `yaml:"logs"`
	LogLevel           string             `yaml:"log_level"`
	Output             GlobalOutputConfig `yaml:"output"`
	Concurrency        int                `yaml:"concurrency"`
	RateLimitPerTarget int                `yaml:"rate_limit_per_target"`
	DryRun             bool               `yaml:"dry_run"`
	Auth               GlobalAuthConfig   `yaml:"auth"`
}

// GlobalOutputConfig controls structured output options.
type GlobalOutputConfig struct {
	JSON bool `yaml:"json"`
}

// GlobalAuthConfig controls outbound proxying or auth.
type GlobalAuthConfig struct {
	HTTPProxy   string `yaml:"http_proxy"`
	SOCKS5Proxy string `yaml:"socks5_proxy"`
	Username    string `yaml:"username"`
	Password    string `yaml:"password"`
}

// DNSConfig captures the DNS module settings.
type DNSConfig struct {
	Enabled           bool          `yaml:"enabled"`
	Nameserver        string        `yaml:"nameserver"`
	Port              int           `yaml:"port"`
	TimeoutMS         int           `yaml:"timeout_ms"`
	Retries           int           `yaml:"retries"`
	QueryTypes        []string      `yaml:"query_types"`
	DOH               DNSDoHConfig  `yaml:"doh"`
	DOT               DNSTLSConfig  `yaml:"dot"`
	DOQ               DNSQUICConfig `yaml:"doq"`
	RecordRawResponse bool          `yaml:"record_raw_response"`
}

// DNSDoHConfig configures the DoH transport.
type DNSDoHConfig struct {
	Enabled      bool     `yaml:"enabled"`
	Nameserver   string   `yaml:"nameserver"`
	BootstrapIPs []string `yaml:"bootstrap_ips"`
	TimeoutMS    int      `yaml:"timeout_ms"`
}

// DNSTLSConfig configures DoT.
type DNSTLSConfig struct {
	Enabled    bool   `yaml:"enabled"`
	Nameserver string `yaml:"nameserver"`
	TimeoutMS  int    `yaml:"timeout_ms"`
}

// DNSQUICConfig configures DoQ.
type DNSQUICConfig struct {
	Enabled    bool   `yaml:"enabled"`
	Nameserver string `yaml:"nameserver"`
	TimeoutMS  int    `yaml:"timeout_ms"`
}

// IPDirectConfig controls direct TCP/TLS probing.
type IPDirectConfig struct {
	Enabled               bool  `yaml:"enabled"`
	Ports                 []int `yaml:"ports"`
	TCPConnectTimeoutMS   int   `yaml:"tcp_connect_timeout_ms"`
	TLSHandshakeIfPort443 bool  `yaml:"tls_handshake_if_port_443"`
	AllowUntrustedCert    bool  `yaml:"allow_untrusted_cert"`
	Retries               int   `yaml:"retries"`
}

// TLSConfig covers TLS/SNI/ECH scenarios.
type TLSConfig struct {
	Enabled   bool         `yaml:"enabled"`
	TimeoutMS int          `yaml:"timeout_ms"`
	SNI       TLSSNIConfig `yaml:"sni"`
	ECH       TLSECHConfig `yaml:"ech"`
}

// TLSSNIConfig toggles SNI usage.
type TLSSNIConfig struct {
	SendSNI bool `yaml:"send_sni"`
}

// TLSECHConfig describes ECH probing strategy.
type TLSECHConfig struct {
	Enabled          bool   `yaml:"enabled"`
	Policy           string `yaml:"policy"`
	TestServerConfig string `yaml:"test_server_config"`
}

// HTTPConfig configures HTTP/HTTPS requests.
type HTTPConfig struct {
	Enabled              bool              `yaml:"enabled"`
	FollowRedirects      bool              `yaml:"follow_redirects"`
	MaxRedirects         int               `yaml:"max_redirects"`
	TimeoutMS            int               `yaml:"timeout_ms"`
	Methods              []string          `yaml:"methods"`
	Headers              map[string]string `yaml:"headers"`
	PathVariants         []string          `yaml:"path_variants"`
	RecordResponseBody   bool              `yaml:"record_response_body"`
	ResponseBodyMaxBytes int               `yaml:"response_body_max_bytes"`
}

// QUICConfig configures QUIC/HTTP3 probing.
type QUICConfig struct {
	Enabled              bool     `yaml:"enabled"`
	TimeoutMS            int      `yaml:"timeout_ms"`
	ALPN                 []string `yaml:"alpn"`
	Versions             []string `yaml:"versions"`
	HandshakeAttempts    int      `yaml:"handshake_attempts"`
	UDPBindAddr          string   `yaml:"udp_bind_addr"`
	RecordInitialPackets bool     `yaml:"record_initial_packets"`
}

// NetworkProbesConfig controls traceroute and ping.
type NetworkProbesConfig struct {
	Traceroute TracerouteConfig `yaml:"traceroute"`
	Ping       PingConfig       `yaml:"ping"`
}

// TracerouteConfig configures traceroute runs.
type TracerouteConfig struct {
	Enabled         bool   `yaml:"enabled"`
	Mode            string `yaml:"mode"`
	MaxHops         int    `yaml:"max_hops"`
	PerHopTimeoutMS int    `yaml:"per_hop_timeout_ms"`
	ProbePorts      []int  `yaml:"probe_ports"`
}

// PingConfig configures ping checks.
type PingConfig struct {
	Enabled    bool `yaml:"enabled"`
	Count      int  `yaml:"count"`
	IntervalMS int  `yaml:"interval_ms"`
	TimeoutMS  int  `yaml:"timeout_ms"`
	PacketSize int  `yaml:"packet_size"`
}

// LoadConfig loads and parses a playbook from disk.
func LoadConfig(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open config %q: %w", path, err)
	}
	defer func(f *os.File) {
		err := f.Close()
		if err != nil {
			fmt.Printf("warning: close config %q: %v\n", path, err)
		}
	}(f)

	cfg, err := ParseConfig(f)
	if err != nil {
		return nil, fmt.Errorf("parse config %q: %w", path, err)
	}
	return cfg, nil
}

// ParseConfig decodes a playbook from an arbitrary reader.
func ParseConfig(r io.Reader) (*Config, error) {
	var cfg Config
	dec := yaml.NewDecoder(r)
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("decode yaml: %w", err)
	}

	cfg.applyDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// Validate ensures required sections are present and sane.
func (c *Config) Validate() error {
	if c == nil {
		return errors.New("config is nil")
	}
	if c.Version <= 0 {
		return errors.New("version must be greater than zero")
	}
	if len(c.Links) == 0 {
		return errors.New("links must not be empty")
	}
	if c.Global.Concurrency <= 0 {
		return errors.New("global.concurrency must be at least 1")
	}
	if c.Global.RateLimitPerTarget < 0 {
		return errors.New("global.rate_limit_per_target cannot be negative")
	}
	if c.DNS.Enabled && len(c.DNS.QueryTypes) == 0 {
		return errors.New("dns.query_types must contain at least one entry when DNS is enabled")
	}
	if c.HTTP.Enabled && len(c.HTTP.Methods) == 0 {
		return errors.New("http.methods must contain at least one entry when HTTP is enabled")
	}
	if c.QUIC.Enabled && len(c.QUIC.ALPN) == 0 {
		return errors.New("quic.alpn must contain at least one entry when QUIC is enabled")
	}
	if c.QUIC.Enabled && len(c.QUIC.Versions) == 0 {
		return errors.New("quic.versions must contain at least one entry when QUIC is enabled")
	}
	return nil
}

func (c *Config) applyDefaults() {
	if c.Global.LogLevel == "" {
		c.Global.LogLevel = "info"
	}
	if c.Global.Concurrency <= 0 {
		c.Global.Concurrency = 1
	}
	if c.Global.RateLimitPerTarget < 0 {
		c.Global.RateLimitPerTarget = 0
	}
	if c.HTTP.RecordResponseBody && c.HTTP.ResponseBodyMaxBytes == 0 {
		c.HTTP.ResponseBodyMaxBytes = 64 * 1024
	}
}
