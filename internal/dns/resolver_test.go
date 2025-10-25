package dns

import (
	"context"
	"net"
	"testing"
	"time"

	mdns "github.com/miekg/dns"

	"github.com/david4958606/DNT/internal/parser"
)

func TestResolverResolve(t *testing.T) {
	serverAddr, shutdown := startTestDNSServer(t, map[uint16][]mdns.RR{
		mdns.TypeA: {
			&mdns.A{
				Hdr: mdns.RR_Header{
					Name:   "example.com.",
					Rrtype: mdns.TypeA,
					Class:  mdns.ClassINET,
					Ttl:    60,
				},
				A: net.ParseIP("1.2.3.4"),
			},
		},
		mdns.TypeTXT: {
			&mdns.TXT{
				Hdr: mdns.RR_Header{
					Name:   "example.com.",
					Rrtype: mdns.TypeTXT,
					Class:  mdns.ClassINET,
					Ttl:    30,
				},
				Txt: []string{"hello=world"},
			},
		},
	})
	defer shutdown()

	cfg := parser.DNSConfig{
		Enabled:    true,
		Nameserver: serverAddr,
		TimeoutMS:  2000,
		QueryTypes: []string{"A", "TXT"},
	}

	resolver, err := NewResolver(cfg)
	{
		if err != nil {
			t.Fatalf("NewResolver error: %v", err)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	result := resolver.Resolve(ctx, parser.DNSTask{Host: "example.com"})
	if len(result.QueryResults) != 2 {
		t.Fatalf("expected 2 query results, got %d", len(result.QueryResults))
	}

	verifyRecord := func(qType string, want ResourceRecord) {
		t.Helper()
		for _, qr := range result.QueryResults {
			if qr.Type != qType {
				continue
			}
			if len(qr.Answers) == 0 {
				t.Fatalf("query %s returned no answers", qType)
			}
			if qr.Answers[0].Data != want.Data {
				t.Fatalf("query %s answer = %s, want %s", qType, qr.Answers[0].Data, want.Data)
			}
			return
		}
		t.Fatalf("query result %s not found", qType)
	}

	verifyRecord("A", ResourceRecord{Data: "1.2.3.4"})
	verifyRecord("TXT", ResourceRecord{Data: "hello=world"})
}

func TestResolverBatchCancellation(t *testing.T) {
	serverAddr, shutdown := startTestDNSServer(t, nil)
	defer shutdown()

	cfg := parser.DNSConfig{
		Enabled:    true,
		Nameserver: serverAddr,
		TimeoutMS:  1000,
		QueryTypes: []string{"A"},
	}
	resolver, err := NewResolver(cfg)
	if err != nil {
		t.Fatalf("NewResolver error: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	_, err = resolver.ResolveBatch(ctx, []parser.DNSTask{{Host: "example.com"}}, Options{Workers: 1})
	if err == nil {
		t.Fatalf("expected cancellation error")
	}
}

func startTestDNSServer(t *testing.T, records map[uint16][]mdns.RR) (string, func()) {
	t.Helper()

	handler := mdns.NewServeMux()
	handler.HandleFunc(".", func(w mdns.ResponseWriter, req *mdns.Msg) {
		m := new(mdns.Msg)
		m.SetReply(req)
		for _, q := range req.Question {
			if recs, ok := records[q.Qtype]; ok {
				for _, rr := range recs {
					m.Answer = append(m.Answer, rr)
				}
			}
		}
		_ = w.WriteMsg(m)
	})

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket error: %v", err)
	}

	server := &mdns.Server{
		PacketConn: pc,
		Handler:    handler,
	}

	go func() {
		_ = server.ActivateAndServe()
	}()

	return pc.LocalAddr().String(), func() {
		_ = server.Shutdown()
		_ = pc.Close()
	}
}
