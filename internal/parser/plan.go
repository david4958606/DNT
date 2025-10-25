package parser

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
)

// Plan describes the concrete tasks produced from a Config that the runtime
// modules can execute.
type Plan struct {
	Config          *Config
	Links           []LinkTarget
	DNSTasks        []DNSTask
	IPDirectTasks   []IPDirectTask
	TLSTasks        []TLSTask
	HTTPTasks       []HTTPTask
	QUICTasks       []QUICTask
	TracerouteTasks []TracerouteTask
	PingTasks       []PingTask
}

// LinkTarget represents a normalized entry from the links list.
type LinkTarget struct {
	Raw      string
	Host     string
	Port     string
	Scheme   string
	Path     string
	IsURL    bool
	IsIP     bool
	IsDomain bool
}

// DNSTask represents a DNS lookup target.
type DNSTask struct {
	Host   string
	Source LinkTarget
}

// IPDirectTask represents a direct TCP/TLS probe target.
type IPDirectTask struct {
	Address string
	Source  LinkTarget
}

// TLSTask represents a TLS handshake target (SNI/ECH permutations happen later).
type TLSTask struct {
	ServerName string
	Source     LinkTarget
}

// HTTPTask represents a base URL whose methods + paths are configured elsewhere.
type HTTPTask struct {
	BaseURL string
	Source  LinkTarget
}

// QUICTask represents a QUIC/HTTP3 handshake target.
type QUICTask struct {
	Host   string
	Source LinkTarget
}

// TracerouteTask represents one traceroute destination.
type TracerouteTask struct {
	Target string
	Source LinkTarget
}

// PingTask represents one ping destination.
type PingTask struct {
	Target string
	Source LinkTarget
}

// BuildPlan converts a parsed Config into a task graph that the executor can consume.
func BuildPlan(cfg *Config) (*Plan, error) {
	if cfg == nil {
		return nil, errors.New("config is nil")
	}

	links, err := normalizeLinks(cfg.Links)
	if err != nil {
		return nil, err
	}

	plan := &Plan{
		Config: cfg,
		Links:  links,
	}

	if cfg.DNS.Enabled {
		plan.DNSTasks = buildDNSTasks(links)
	}
	if cfg.IPDirect.Enabled {
		plan.IPDirectTasks = buildIPDirectTasks(links)
	}
	if cfg.TLS.Enabled {
		plan.TLSTasks = buildTLSTasks(links)
	}
	if cfg.HTTP.Enabled {
		plan.HTTPTasks = buildHTTPTasks(links)
	}
	if cfg.QUIC.Enabled {
		plan.QUICTasks = buildQUICTasks(links)
	}
	if cfg.NetworkProbes.Traceroute.Enabled {
		plan.TracerouteTasks = buildTracerouteTasks(links)
	}
	if cfg.NetworkProbes.Ping.Enabled {
		plan.PingTasks = buildPingTasks(links)
	}

	return plan, nil
}

func buildDNSTasks(links []LinkTarget) []DNSTask {
	seen := make(map[string]struct{})
	var tasks []DNSTask
	for _, link := range links {
		if link.Host == "" || link.IsIP {
			continue
		}
		host := link.Host
		if _, ok := seen[host]; ok {
			continue
		}
		seen[host] = struct{}{}
		tasks = append(tasks, DNSTask{
			Host:   host,
			Source: link,
		})
	}
	return tasks
}

func buildIPDirectTasks(links []LinkTarget) []IPDirectTask {
	seen := make(map[string]struct{})
	var tasks []IPDirectTask
	for _, link := range links {
		if !link.IsIP {
			continue
		}
		addr := link.Host
		if _, ok := seen[addr]; ok {
			continue
		}
		seen[addr] = struct{}{}
		tasks = append(tasks, IPDirectTask{
			Address: addr,
			Source:  link,
		})
	}
	return tasks
}

func buildTLSTasks(links []LinkTarget) []TLSTask {
	seen := make(map[string]struct{})
	var tasks []TLSTask
	for _, link := range links {
		if link.Host == "" || link.IsIP {
			continue
		}
		host := link.Host
		if _, ok := seen[host]; ok {
			continue
		}
		seen[host] = struct{}{}
		tasks = append(tasks, TLSTask{
			ServerName: host,
			Source:     link,
		})
	}
	return tasks
}

func buildHTTPTasks(links []LinkTarget) []HTTPTask {
	seen := make(map[string]struct{})
	var tasks []HTTPTask
	for _, link := range links {
		base := link.BaseURL("")
		if base == "" {
			continue
		}
		key := strings.ToLower(base)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		tasks = append(tasks, HTTPTask{
			BaseURL: base,
			Source:  link,
		})
	}
	return tasks
}

func buildQUICTasks(links []LinkTarget) []QUICTask {
	seen := make(map[string]struct{})
	var tasks []QUICTask
	for _, link := range links {
		if link.Host == "" || link.IsIP {
			continue
		}
		host := link.Host
		if _, ok := seen[host]; ok {
			continue
		}
		seen[host] = struct{}{}
		tasks = append(tasks, QUICTask{
			Host:   host,
			Source: link,
		})
	}
	return tasks
}

func buildTracerouteTasks(links []LinkTarget) []TracerouteTask {
	seen := make(map[string]struct{})
	var tasks []TracerouteTask
	for _, link := range links {
		host := link.Host
		if host == "" {
			continue
		}
		if _, ok := seen[host]; ok {
			continue
		}
		seen[host] = struct{}{}
		tasks = append(tasks, TracerouteTask{
			Target: host,
			Source: link,
		})
	}
	return tasks
}

func buildPingTasks(links []LinkTarget) []PingTask {
	seen := make(map[string]struct{})
	var tasks []PingTask
	for _, link := range links {
		host := link.Host
		if host == "" {
			continue
		}
		if _, ok := seen[host]; ok {
			continue
		}
		seen[host] = struct{}{}
		tasks = append(tasks, PingTask{
			Target: host,
			Source: link,
		})
	}
	return tasks
}

func normalizeLinks(links []string) ([]LinkTarget, error) {
	result := make([]LinkTarget, 0, len(links))
	for idx, raw := range links {
		target, err := parseLink(raw)
		if err != nil {
			return nil, fmt.Errorf("links[%d]: %w", idx, err)
		}
		result = append(result, target)
	}
	return result, nil
}

func parseLink(raw string) (LinkTarget, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return LinkTarget{}, errors.New("link cannot be empty")
	}

	target := LinkTarget{Raw: trimmed}
	if strings.Contains(trimmed, "://") {
		u, err := url.Parse(trimmed)
		if err != nil {
			return target, fmt.Errorf("invalid URL %q: %w", trimmed, err)
		}
		if u.Host == "" {
			return target, fmt.Errorf("invalid URL %q: missing host", trimmed)
		}
		host := u.Hostname()
		target.IsURL = true
		target.Scheme = strings.ToLower(u.Scheme)
		target.Host = normalizeHost(host)
		target.Port = u.Port()
		target.Path = u.EscapedPath()
		target.IsIP = net.ParseIP(host) != nil
		target.IsDomain = !target.IsIP
		return target, nil
	}

	if strings.Contains(trimmed, "/") {
		return target, fmt.Errorf("link %q looks like a path: please include a scheme", trimmed)
	}

	if ip := net.ParseIP(trimmed); ip != nil {
		target.Host = ip.String()
		target.IsIP = true
		return target, nil
	}

	if strings.Contains(trimmed, ":") {
		host, port, err := net.SplitHostPort(trimmed)
		if err != nil {
			return target, fmt.Errorf("invalid host:port %q: %w", trimmed, err)
		}
		if host == "" {
			return target, fmt.Errorf("invalid host:port %q: host is empty", trimmed)
		}
		target.Port = port
		if ip := net.ParseIP(host); ip != nil {
			target.Host = ip.String()
			target.IsIP = true
		} else {
			target.Host = normalizeHost(host)
			target.IsDomain = true
		}
		return target, nil
	}

	target.Host = normalizeHost(trimmed)
	target.IsDomain = true
	return target, nil
}

func (l LinkTarget) BaseURL(defaultScheme string) string {
	host := l.hostWithOptionalPort()
	if host == "" {
		return ""
	}

	scheme := l.Scheme
	if scheme == "" {
		scheme = defaultScheme
	}
	if scheme == "" {
		if l.IsIP {
			scheme = "http"
		} else {
			scheme = "https"
		}
	}

	return fmt.Sprintf("%s://%s", scheme, host)
}

func (l LinkTarget) hostWithOptionalPort() string {
	if l.Host == "" {
		return ""
	}
	if l.Port != "" {
		return net.JoinHostPort(l.Host, l.Port)
	}
	if strings.Contains(l.Host, ":") {
		return fmt.Sprintf("[%s]", l.Host)
	}
	return l.Host
}

func normalizeHost(host string) string {
	host = strings.TrimSuffix(host, ".")
	return strings.ToLower(host)
}
