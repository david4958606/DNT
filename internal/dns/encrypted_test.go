package dns

import "testing"

func TestParseDoTNameserver(t *testing.T) {
	cases := []struct {
		input    string
		wantHost string
		wantAddr string
	}{
		{"tls://dns.example.com:853", "dns.example.com", "dns.example.com:853"},
		{"dns.example.com", "dns.example.com", "dns.example.com:853"},
		{"1.1.1.1:853", "1.1.1.1", "1.1.1.1:853"},
	}

	for _, tc := range cases {
		host, addr, err := parseDoTNameserver(tc.input)
		if err != nil {
			t.Fatalf("parseDoTNameserver(%q) unexpected error: %v", tc.input, err)
		}
		if host != tc.wantHost || addr != tc.wantAddr {
			t.Fatalf("parseDoTNameserver(%q) = (%q, %q), want (%q, %q)", tc.input, host, addr, tc.wantHost, tc.wantAddr)
		}
	}

	if _, _, err := parseDoTNameserver("http://bad"); err == nil {
		t.Fatal("expected error for non-tls scheme")
	}
}

func TestParseDoHNameserver(t *testing.T) {
	host, full, err := parseDoHNameserver("https://resolver.example.com/dns-query")
	if err != nil {
		t.Fatalf("parseDoHNameserver error: %v", err)
	}
	if host != "resolver.example.com" {
		t.Fatalf("host = %q, want resolver.example.com", host)
	}
	if full != "https://resolver.example.com/dns-query" {
		t.Fatalf("full = %q, want original url", full)
	}

	if _, _, err := parseDoHNameserver("http://resolver.example.com"); err == nil {
		t.Fatal("expected error for non-https scheme")
	}
}
