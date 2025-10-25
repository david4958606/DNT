package dns

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"time"
	"unsafe"

	tdns "github.com/fumiama/terasu/dns"
	mdns "github.com/miekg/dns"

	"github.com/david4958606/DNT/internal/parser"
)

var errDoHUnsupportedType = errors.New("doh: unsupported rr type")

type encryptedResolver struct {
	doh *dohResolver
	dot *dotResolver
}

func newEncryptedResolver(cfg parser.DNSConfig) (*encryptedResolver, error) {
	var (
		doh *dohResolver
		dot *dotResolver
		err error
	)

	if cfg.DOH.Enabled {
		doh, err = newDoHResolver(cfg.DOH)
		if err != nil {
			return nil, fmt.Errorf("doh: %w", err)
		}
	}
	if cfg.DOT.Enabled {
		dot, err = newDoTResolver(cfg.DOT)
		if err != nil {
			return nil, fmt.Errorf("dot: %w", err)
		}
	}

	if doh == nil && dot == nil {
		return nil, nil
	}

	return &encryptedResolver{
		doh: doh,
		dot: dot,
	}, nil
}

func (e *encryptedResolver) Query(ctx context.Context, host string, qtype queryType, recordRaw bool) ([]QueryResult, []QueryError) {
	var (
		results []QueryResult
		errs    []QueryError
	)

	if e.dot != nil {
		if res, err := e.dot.Query(ctx, host, qtype, recordRaw); err != nil {
			errs = append(errs, QueryError{
				Type:      qtype.name,
				Transport: transportDoT,
				Error:     err.Error(),
			})
		} else if len(res.Answers) > 0 {
			results = append(results, res)
		}
	}

	if e.doh != nil {
		if res, err := e.doh.Query(ctx, host, qtype); err != nil {
			if !errors.Is(err, errDoHUnsupportedType) {
				errs = append(errs, QueryError{
					Type:      qtype.name,
					Transport: transportDoH,
					Error:     err.Error(),
				})
			}
		} else if len(res.Answers) > 0 {
			results = append(results, res)
		}
	}

	return results, errs
}

type dohResolver struct {
	list    *tdns.List
	timeout time.Duration
	mu      sync.Mutex
}

func newDoHResolver(cfg parser.DNSDoHConfig) (*dohResolver, error) {
	if strings.TrimSpace(cfg.Nameserver) == "" {
		return nil, errors.New("nameserver must be set")
	}

	host, dohURL, err := parseDoHNameserver(cfg.Nameserver)
	if err != nil {
		return nil, err
	}

	list, err := buildDNSList(&tdns.Config{
		Servers: map[string][]string{
			host: {dohURL},
		},
	})
	if err != nil {
		return nil, err
	}

	timeout := durationFromMillis(cfg.TimeoutMS, 4*time.Second)

	return &dohResolver{
		list:    list,
		timeout: timeout,
	}, nil
}

func (d *dohResolver) Query(ctx context.Context, host string, qtype queryType) (QueryResult, error) {
	if qtype.code != mdns.TypeA && qtype.code != mdns.TypeAAAA {
		return QueryResult{}, errDoHUnsupportedType
	}

	ctx, cancel := context.WithTimeout(ctx, d.timeout)
	defer cancel()

	// Avoid copying tdns.List (contains a lock) by swapping only inner fields
	d.mu.Lock()
	restoreV4, err := swapTDNSList(&tdns.IPv4Servers, d.list)
	if err != nil {
		d.mu.Unlock()
		return QueryResult{}, err
	}
	restoreV6, err := swapTDNSList(&tdns.IPv6Servers, d.list)
	if err != nil {
		// restore v4 before returning
		restoreV4()
		d.mu.Unlock()
		return QueryResult{}, err
	}
	defer func() {
		restoreV6()
		restoreV4()
		d.mu.Unlock()
	}()

	addrs, err := tdns.LookupHost(ctx, host)
	if err != nil {
		return QueryResult{}, err
	}

	records := buildAddressRecords(host, addrs, qtype)
	if len(records) == 0 {
		return QueryResult{}, fmt.Errorf("doh: no %s answers", qtype.name)
	}

	return QueryResult{
		Type:      qtype.name,
		Transport: transportDoH,
		Answers:   records,
	}, nil
}

type dotResolver struct {
	list    *tdns.List
	timeout time.Duration
}

func newDoTResolver(cfg parser.DNSTLSConfig) (*dotResolver, error) {
	if strings.TrimSpace(cfg.Nameserver) == "" {
		return nil, errors.New("nameserver must be set")
	}

	host, addr, err := parseDoTNameserver(cfg.Nameserver)
	if err != nil {
		return nil, err
	}

	list, err := buildDNSList(&tdns.Config{
		Servers: map[string][]string{
			host: {addr},
		},
	})
	if err != nil {
		return nil, err
	}

	timeout := durationFromMillis(cfg.TimeoutMS, 4*time.Second)

	return &dotResolver{
		list:    list,
		timeout: timeout,
	}, nil
}

func (d *dotResolver) Query(ctx context.Context, host string, qtype queryType, recordRaw bool) (QueryResult, error) {
	ctx, cancel := context.WithTimeout(ctx, d.timeout)
	defer cancel()

	conn, err := d.list.DialContext(ctx, &net.Dialer{Timeout: d.timeout})
	if err != nil {
		return QueryResult{}, err
	}
	defer func(conn *tls.Conn) {
		err := conn.Close()
		if err != nil {
			fmt.Printf("warning: close dot connection: %v\n", err)
		}
	}(conn)

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	} else {
		_ = conn.SetDeadline(time.Now().Add(d.timeout))
	}

	msg := new(mdns.Msg)
	msg.SetQuestion(mdns.Fqdn(host), qtype.code)

	dnsConn := &mdns.Conn{Conn: conn}
	client := &mdns.Client{
		Net:     "tcp-tls",
		Timeout: d.timeout,
	}

	response, _, err := client.ExchangeWithConnContext(ctx, msg, dnsConn)
	if err != nil {
		return QueryResult{}, err
	}

	return buildQueryResult(response, qtype, recordRaw, transportDoT), nil
}

func buildDNSList(cfg *tdns.Config) (*tdns.List, error) {
	if cfg == nil {
		return nil, errors.New("nil dns config")
	}
	lst := &tdns.List{}
	if err := initDNSList(lst); err != nil {
		return nil, err
	}
	lst.Add(cfg)
	return lst, nil
}

func initDNSList(lst *tdns.List) error {
	val := reflect.ValueOf(lst).Elem()
	for _, name := range []string{"hostseq"} {
		field := val.FieldByName(name)
		if !field.IsValid() {
			return fmt.Errorf("terasu dns: missing field %s", name)
		}
		setUnexported(field, reflect.MakeSlice(field.Type(), 0, 0))
	}
	for _, name := range []string{"m", "b"} {
		field := val.FieldByName(name)
		if !field.IsValid() {
			return fmt.Errorf("terasu dns: missing field %s", name)
		}
		setUnexported(field, reflect.MakeMap(field.Type()))
	}
	return nil
}

// swapTDNSList swaps the internal fields of dst with those from src and returns
// a restore function that reverts dst to its previous state. This avoids copying
// the tdns.List struct itself (which contains a lock), fixing copylock issues.
func swapTDNSList(dst, src *tdns.List) (restore func(), err error) {
	if dst == nil || src == nil {
		return func() {}, errors.New("nil list")
	}
	valDst := reflect.ValueOf(dst).Elem()
	valSrc := reflect.ValueOf(src).Elem()

	type savedField struct {
		name string
		val  reflect.Value
	}
	var saved []savedField

	for _, name := range []string{"hostseq", "m", "b"} {
		fDst := valDst.FieldByName(name)
		if !fDst.IsValid() {
			return func() {}, fmt.Errorf("terasu dns: missing field %s", name)
		}
		fSrc := valSrc.FieldByName(name)
		if !fSrc.IsValid() {
			return func() {}, fmt.Errorf("terasu dns: missing field %s", name)
		}

		// Save a copy of the old value (slice/map header) so we can restore later
		old := reflect.New(fDst.Type()).Elem()
		old.Set(fDst)
		saved = append(saved, savedField{name: name, val: old})

		// Set dst's field to src's field without copying the whole struct
		setUnexported(fDst, fSrc)
	}

	return func() {
		for _, s := range saved {
			f := valDst.FieldByName(s.name)
			if f.IsValid() {
				setUnexported(f, s.val)
			}
		}
	}, nil
}

func setUnexported(field, value reflect.Value) {
	ptr := unsafe.Pointer(field.UnsafeAddr())
	reflect.NewAt(field.Type(), ptr).Elem().Set(value)
}

func parseDoTNameserver(raw string) (string, string, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", "", errors.New("dot nameserver is empty")
	}

	var target string
	if strings.Contains(value, "://") {
		u, err := url.Parse(value)
		if err != nil {
			return "", "", fmt.Errorf("invalid dot url: %w", err)
		}
		if u.Scheme != "tls" {
			return "", "", fmt.Errorf("unsupported dot scheme %q", u.Scheme)
		}
		target = u.Host
	} else {
		target = value
	}

	host, port, err := net.SplitHostPort(target)
	if err != nil {
		if strings.Contains(err.Error(), "missing port") {
			host = target
			port = "853"
		} else {
			return "", "", fmt.Errorf("invalid dot nameserver %q: %w", target, err)
		}
	}
	if port == "" {
		port = "853"
	}

	addr := net.JoinHostPort(host, port)
	return host, addr, nil
}

func parseDoHNameserver(raw string) (string, string, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", "", errors.New("doh nameserver is empty")
	}
	u, err := url.Parse(value)
	if err != nil {
		return "", "", fmt.Errorf("invalid doh url: %w", err)
	}
	if u.Scheme != "https" {
		return "", "", fmt.Errorf("unsupported doh scheme %q", u.Scheme)
	}
	if u.Host == "" {
		return "", "", errors.New("doh url missing host")
	}
	return u.Hostname(), value, nil
}

func buildAddressRecords(host string, addrs []string, qtype queryType) []ResourceRecord {
	fqdn := mdns.Fqdn(host)
	var records []ResourceRecord
	for _, addr := range addrs {
		if qtype.code == mdns.TypeA && strings.Contains(addr, ":") {
			continue
		}
		if qtype.code == mdns.TypeAAAA && !strings.Contains(addr, ":") {
			continue
		}
		records = append(records, ResourceRecord{
			Name: fqdn,
			Type: qtype.name,
			Data: addr,
		})
	}
	return records
}

func durationFromMillis(ms int, fallback time.Duration) time.Duration {
	if ms <= 0 {
		return fallback
	}
	return time.Duration(ms) * time.Millisecond
}
