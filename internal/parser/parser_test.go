package parser

import (
	"path/filepath"
	"runtime"
	"testing"
)

func TestParseConfigExample(t *testing.T) {
	cfg := loadExampleConfig(t)

	if cfg.Version != 1 {
		t.Fatalf("expected version 1, got %d", cfg.Version)
	}
	if got, want := cfg.Global.Concurrency, 10; got != want {
		t.Fatalf("global.concurrency = %d, want %d", got, want)
	}
	if !cfg.DNS.Enabled {
		t.Fatalf("expected dns.enabled to be true")
	}
	if got, want := len(cfg.Links), 4; got != want {
		t.Fatalf("links length = %d, want %d", got, want)
	}
	if got, want := cfg.HTTP.Methods[0], "GET"; got != want {
		t.Fatalf("http.methods[0] = %s, want %s", got, want)
	}
}

func TestBuildPlanFromExample(t *testing.T) {
	cfg := loadExampleConfig(t)

	plan, err := BuildPlan(cfg)
	if err != nil {
		t.Fatalf("BuildPlan error: %v", err)
	}
	if plan.Config != cfg {
		t.Fatalf("plan.Config was not the same pointer passed in")
	}
	if got, want := len(plan.Links), len(cfg.Links); got != want {
		t.Fatalf("plan links length = %d, want %d", got, want)
	}

	expectHosts(t, "dns", extractDNSHosts(plan.DNSTasks), []string{
		"www.baidu.com",
		"www.bing.com",
		"www.weixin.qq.com",
	})

	expectHosts(t, "tls", extractTLSServerNames(plan.TLSTasks), []string{
		"www.baidu.com",
		"www.bing.com",
		"www.weixin.qq.com",
	})

	expectHosts(t, "quic", extractQUICTargets(plan.QUICTasks), []string{
		"www.baidu.com",
		"www.bing.com",
		"www.weixin.qq.com",
	})

	expectHosts(t, "ip-direct", extractIPAddresses(plan.IPDirectTasks), []string{
		"114.114.114.114",
	})

	expectHosts(t, "http", extractHTTPBases(plan.HTTPTasks), []string{
		"https://www.baidu.com",
		"https://www.bing.com",
		"https://www.weixin.qq.com",
		"http://114.114.114.114",
	})

	expectHosts(t, "traceroute", extractTargets(plan.TracerouteTasks), []string{
		"www.baidu.com",
		"www.bing.com",
		"www.weixin.qq.com",
		"114.114.114.114",
	})

	expectHosts(t, "ping", extractPingTargets(plan.PingTasks), []string{
		"www.baidu.com",
		"www.bing.com",
		"www.weixin.qq.com",
		"114.114.114.114",
	})
}

func loadExampleConfig(t *testing.T) *Config {
	t.Helper()
	path := exampleConfigPath(t)
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig(%s) error: %v", path, err)
	}
	return cfg
}

func exampleConfigPath(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	root := filepath.Join(filepath.Dir(filename), "..", "..")
	return filepath.Join(root, "docs", "config.example.yaml")
}

func expectHosts[T comparable](t *testing.T, name string, got, want []T) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s task count = %d, want %d", name, len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("%s task[%d] = %v, want %v", name, i, got[i], want[i])
		}
	}
}

func extractDNSHosts(tasks []DNSTask) []string {
	hosts := make([]string, 0, len(tasks))
	for _, task := range tasks {
		hosts = append(hosts, task.Host)
	}
	return hosts
}

func extractTLSServerNames(tasks []TLSTask) []string {
	names := make([]string, 0, len(tasks))
	for _, task := range tasks {
		names = append(names, task.ServerName)
	}
	return names
}

func extractQUICTargets(tasks []QUICTask) []string {
	hosts := make([]string, 0, len(tasks))
	for _, task := range tasks {
		hosts = append(hosts, task.Host)
	}
	return hosts
}

func extractIPAddresses(tasks []IPDirectTask) []string {
	hosts := make([]string, 0, len(tasks))
	for _, task := range tasks {
		hosts = append(hosts, task.Address)
	}
	return hosts
}

func extractHTTPBases(tasks []HTTPTask) []string {
	bases := make([]string, 0, len(tasks))
	for _, task := range tasks {
		bases = append(bases, task.BaseURL)
	}
	return bases
}

func extractTargets(tasks []TracerouteTask) []string {
	hosts := make([]string, 0, len(tasks))
	for _, task := range tasks {
		hosts = append(hosts, task.Target)
	}
	return hosts
}

func extractPingTargets(tasks []PingTask) []string {
	hosts := make([]string, 0, len(tasks))
	for _, task := range tasks {
		hosts = append(hosts, task.Target)
	}
	return hosts
}
