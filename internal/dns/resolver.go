package dns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	mdns "github.com/miekg/dns"

	"github.com/david4958606/DNT/internal/parser"
)

// Options controls how ResolveBatch executes.
type Options struct {
	// Workers limits concurrency. Values <=0 default to len(tasks) or 1.
	Workers int
}

// Resolver executes DNS tasks against the configured resolvers.
type Resolver struct {
	cfg         parser.DNSConfig
	serverAddr  string
	timeout     time.Duration
	queryTypes  []queryType
	udpClient   *mdns.Client
	tcpClient   *mdns.Client
	rawRecorder bool
}

type queryType struct {
	name string
	code uint16
}

// Result captures answers/errors for a single DNSTask.
type Result struct {
	Task         parser.DNSTask
	QueryResults []QueryResult
	QueryErrors  []QueryError
}

// QueryResult represents the records returned for a single RR type.
type QueryResult struct {
	Type    string
	Answers []ResourceRecord
	Raw     []byte
}

// ResourceRecord is a simplified view of dns.RR.
type ResourceRecord struct {
	Name string
	Type string
	TTL  uint32
	Data string
}

// QueryError captures failures for individual question types.
type QueryError struct {
	Type  string
	Error string
}

// NewResolver validates DNS config and prepares clients.
func NewResolver(cfg parser.DNSConfig) (*Resolver, error) {
	if !cfg.Enabled {
		return nil, errors.New("dns module disabled")
	}
	if len(cfg.QueryTypes) == 0 {
		return nil, errors.New("dns.query_types must not be empty")
	}

	address, err := buildServerAddress(cfg.Nameserver, cfg.Port)
	if err != nil {
		return nil, err
	}

	timeout := time.Duration(cfg.TimeoutMS) * time.Millisecond
	if timeout <= 0 {
		timeout = 3 * time.Second
	}

	qTypes, err := normalizeQueryTypes(cfg.QueryTypes)
	if err != nil {
		return nil, err
	}

	return &Resolver{
		cfg:        cfg,
		serverAddr: address,
		timeout:    timeout,
		queryTypes: qTypes,
		udpClient: &mdns.Client{
			Net:     "udp",
			Timeout: timeout,
		},
		tcpClient: &mdns.Client{
			Net:     "tcp",
			Timeout: timeout,
		},
		rawRecorder: cfg.RecordRawResponse,
	}, nil
}

// ResolveBatch concurrently resolves the provided tasks and returns results in the same order.
func (r *Resolver) ResolveBatch(ctx context.Context, tasks []parser.DNSTask, opts Options) ([]Result, error) {
	if len(tasks) == 0 {
		return nil, nil
	}

	workers := opts.Workers
	if workers <= 0 || workers > len(tasks) {
		if len(tasks) == 0 {
			workers = 1
		} else {
			workers = len(tasks)
		}
	}

	type job struct {
		idx  int
		task parser.DNSTask
	}

	jobCh := make(chan job)
	res := make([]Result, len(tasks))
	var wg sync.WaitGroup

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobCh {
				res[j.idx] = r.Resolve(ctx, j.task)
			}
		}()
	}

	for idx, task := range tasks {
		select {
		case <-ctx.Done():
			close(jobCh)
			wg.Wait()
			return nil, ctx.Err()
		case jobCh <- job{idx: idx, task: task}:
		}
	}
	close(jobCh)
	wg.Wait()

	return res, nil
}

// Resolve executes all configured query types for a single task.
func (r *Resolver) Resolve(ctx context.Context, task parser.DNSTask) Result {
	result := Result{Task: task}
	for _, qtype := range r.queryTypes {
		qRes, qErr := r.queryOnce(ctx, task.Host, qtype)
		if qErr != nil {
			result.QueryErrors = append(result.QueryErrors, QueryError{
				Type:  qtype.name,
				Error: qErr.Error(),
			})
			continue
		}
		result.QueryResults = append(result.QueryResults, qRes)
	}
	return result
}

func (r *Resolver) queryOnce(ctx context.Context, host string, qtype queryType) (QueryResult, error) {
	msg := new(mdns.Msg)
	msg.SetQuestion(mdns.Fqdn(host), qtype.code)

	response, err := r.exchangeContext(ctx, msg)
	if err != nil {
		return QueryResult{}, err
	}
	var raw []byte
	if r.rawRecorder {
		if packed, packErr := response.Pack(); packErr == nil {
			raw = packed
		}
	}
	answers := make([]ResourceRecord, 0, len(response.Answer))
	for _, rr := range response.Answer {
		if rr.Header().Rrtype != qtype.code {
			continue
		}
		answers = append(answers, simplifyRR(rr))
	}

	qRes := QueryResult{
		Type:    qtype.name,
		Answers: answers,
	}
	if len(raw) > 0 {
		qRes.Raw = append([]byte(nil), raw...)
	}
	return qRes, nil
}

func (r *Resolver) exchangeContext(ctx context.Context, msg *mdns.Msg) (*mdns.Msg, error) {
	// Try UDP first, fall back to TCP when truncated or UDP fails.
	response, _, err := r.udpClient.ExchangeContext(ctx, msg, r.serverAddr)
	if err == nil && !response.Truncated {
		return response, nil
	}
	if err == nil && response.Truncated {
		// Fall through to TCP for full response.
	}
	response, _, err = r.tcpClient.ExchangeContext(ctx, msg, r.serverAddr)
	if err != nil {
		return nil, err
	}
	return response, nil
}

func buildServerAddress(nameserver string, port int) (string, error) {
	if nameserver == "" {
		return "", errors.New("dns.nameserver must be set")
	}

	if strings.Contains(nameserver, "://") {
		return "", fmt.Errorf("nameserver %q looks like a URL; transport-specific handlers are not implemented yet", nameserver)
	}

	if strings.Contains(nameserver, ":") {
		return nameserver, nil
	}

	if port == 0 {
		port = 53
	}
	return net.JoinHostPort(nameserver, fmt.Sprintf("%d", port)), nil
}

func normalizeQueryTypes(types []string) ([]queryType, error) {
	result := make([]queryType, 0, len(types))
	seen := make(map[uint16]struct{})
	for _, t := range types {
		name := strings.ToUpper(strings.TrimSpace(t))
		if name == "" {
			return nil, errors.New("query type cannot be empty")
		}
		code, ok := mdns.StringToType[name]
		if !ok {
			return nil, fmt.Errorf("unsupported query type %q", t)
		}
		if _, dup := seen[code]; dup {
			continue
		}
		seen[code] = struct{}{}
		result = append(result, queryType{
			name: name,
			code: code,
		})
	}
	return result, nil
}

func simplifyRR(rr mdns.RR) ResourceRecord {
	if rr == nil {
		return ResourceRecord{}
	}
	base := ResourceRecord{
		Name: rr.Header().Name,
		Type: mdns.TypeToString[rr.Header().Rrtype],
		TTL:  rr.Header().Ttl,
		Data: rr.String(),
	}

	switch v := rr.(type) {
	case *mdns.A:
		base.Data = v.A.String()
	case *mdns.AAAA:
		base.Data = v.AAAA.String()
	case *mdns.CNAME:
		base.Data = v.Target
	case *mdns.TXT:
		base.Data = strings.Join(v.Txt, " ")
	case *mdns.MX:
		base.Data = fmt.Sprintf("%d %s", v.Preference, v.Mx)
	case *mdns.NS:
		base.Data = v.Ns
	case *mdns.PTR:
		base.Data = v.Ptr
	case *mdns.SOA:
		base.Data = fmt.Sprintf("%s %s %d %d %d %d %d",
			v.Ns, v.Mbox, v.Serial, v.Refresh, v.Retry, v.Expire, v.Minttl)
	case *mdns.SRV:
		base.Data = fmt.Sprintf("%d %d %d %s", v.Priority, v.Weight, v.Port, v.Target)
	}
	return base
}
