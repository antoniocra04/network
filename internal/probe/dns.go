package probe

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// ErrNXDomain means the resolver claims the name does not exist.
var ErrNXDomain = errors.New("NXDOMAIN")

func buildQuery(name string) (uint16, []byte, error) {
	id := uint16(rand.IntN(0xffff))
	n, err := dnsmessage.NewName(dns(name))
	if err != nil {
		return 0, nil, err
	}
	m := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: id, RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: n, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}},
	}
	b, err := m.Pack()
	return id, b, err
}

func dns(name string) string {
	if len(name) > 0 && name[len(name)-1] != '.' {
		return name + "."
	}
	return name
}

func parseAnswer(b []byte, id uint16) ([]net.IP, error) {
	var m dnsmessage.Message
	if err := m.Unpack(b); err != nil {
		return nil, err
	}
	if m.Header.ID != id {
		return nil, errors.New("чужой ответ DNS")
	}
	if m.Header.RCode == dnsmessage.RCodeNameError {
		return nil, ErrNXDomain
	}
	if m.Header.RCode != dnsmessage.RCodeSuccess {
		return nil, fmt.Errorf("DNS: %s", m.Header.RCode)
	}
	var ips []net.IP
	for _, a := range m.Answers {
		if r, ok := a.Body.(*dnsmessage.AResource); ok {
			ips = append(ips, net.IP(r.A[:]))
		}
	}
	if len(ips) == 0 {
		return nil, errors.New("нет A-записей")
	}
	return ips, nil
}

// QueryUDP asks a specific resolver over plain UDP/53.
func QueryUDP(ctx context.Context, server, name string) ([]net.IP, time.Duration, error) {
	id, q, err := buildQuery(name)
	if err != nil {
		return nil, 0, err
	}
	var d net.Dialer
	c, err := d.DialContext(ctx, "udp", net.JoinHostPort(server, "53"))
	if err != nil {
		return nil, 0, err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	start := time.Now()
	if _, err := c.Write(q); err != nil {
		return nil, 0, err
	}
	buf := make([]byte, 1500)
	n, err := c.Read(buf)
	if err != nil {
		return nil, 0, err
	}
	ips, err := parseAnswer(buf[:n], id)
	return ips, time.Since(start), err
}

// LookupSystem resolves through the OS resolver (the router or ISP DNS).
func LookupSystem(ctx context.Context, name string) ([]net.IP, time.Duration, error) {
	start := time.Now()
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip4", name)
	el := time.Since(start)
	var de *net.DNSError
	if errors.As(err, &de) && de.IsNotFound {
		return nil, el, ErrNXDomain
	}
	return ips, el, err
}

// DoH resolvers used as a reference. They are reached by IP so that
// a tampered system resolver cannot redirect them.
type dohServer struct {
	Name string
	URL  string
	IP   string
}

var dohServers = []dohServer{
	{"Cloudflare", "https://cloudflare-dns.com/dns-query", "1.1.1.1"},
	{"Google", "https://dns.google/dns-query", "8.8.8.8"},
	{"Яндекс", "https://common.dot.dns.yandex.net/dns-query", "77.88.8.8"},
}

func dohClient(ip string) *http.Client {
	return &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				_, port, _ := net.SplitHostPort(addr)
				var d net.Dialer
				return d.DialContext(ctx, network, net.JoinHostPort(ip, port))
			},
			TLSClientConfig:   &tls.Config{MinVersion: tls.VersionTLS12},
			ForceAttemptHTTP2: true,
		},
	}
}

var dohClients = func() map[string]*http.Client {
	m := map[string]*http.Client{}
	for _, s := range dohServers {
		m[s.Name] = dohClient(s.IP)
	}
	return m
}()

func queryDoH(ctx context.Context, s dohServer, name string) ([]net.IP, error) {
	id, q, err := buildQuery(name)
	if err != nil {
		return nil, err
	}
	req, _ := http.NewRequestWithContext(ctx, "POST", s.URL, bytes.NewReader(q))
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	resp, err := dohClients[s.Name].Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("DoH %s: HTTP %d", s.Name, resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 65535))
	if err != nil {
		return nil, err
	}
	// DoH sends ID 0 back as-is per RFC 8484 recommendations, but we set it.
	return parseAnswer(b, id)
}

type refEntry struct {
	ips []net.IP
	via string
	err error
	at  time.Time
}

var (
	refMu    sync.Mutex
	refCache = map[string]refEntry{}
)

// LookupReference resolves through encrypted DNS, trying servers in order.
// Answers are cached for ten minutes.
func LookupReference(ctx context.Context, name string) ([]net.IP, string, error) {
	refMu.Lock()
	e, ok := refCache[name]
	refMu.Unlock()
	if ok && time.Since(e.at) < 10*time.Minute && e.err == nil {
		return e.ips, e.via, nil
	}
	var lastErr error
	for _, s := range dohServers {
		ips, err := queryDoH(ctx, s, name)
		if err == nil || errors.Is(err, ErrNXDomain) {
			refMu.Lock()
			refCache[name] = refEntry{ips: ips, via: s.Name, err: err, at: time.Now()}
			refMu.Unlock()
			return ips, s.Name, err
		}
		lastErr = err
	}
	return nil, "", fmt.Errorf("зашифрованный DNS недоступен: %w", lastErr)
}

// DoHAvailable reports which reference resolvers answer at all.
func DoHAvailable(ctx context.Context) map[string]error {
	out := map[string]error{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, s := range dohServers {
		wg.Add(1)
		go func(s dohServer) {
			defer wg.Done()
			_, err := queryDoH(ctx, s, "ya.ru")
			mu.Lock()
			out[s.Name] = err
			mu.Unlock()
		}(s)
	}
	wg.Wait()
	return out
}

func overlap(a, b []net.IP) bool {
	for _, x := range a {
		for _, y := range b {
			if x.Equal(y) {
				return true
			}
		}
	}
	return false
}

func suspicious(ips []net.IP) bool {
	for _, ip := range ips {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() {
			return true
		}
	}
	return false
}

// LookupDoHVia asks one named reference resolver ("Cloudflare", "Google",
// "Яндекс") without caching.
func LookupDoHVia(ctx context.Context, server, name string) ([]net.IP, error) {
	for _, s := range dohServers {
		if s.Name == server {
			return queryDoH(ctx, s, name)
		}
	}
	return nil, fmt.Errorf("неизвестный DoH-сервер %s", server)
}
