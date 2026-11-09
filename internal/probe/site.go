package probe

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

// Kind classifies why a site does or does not open.
type Kind string

const (
	KindOK          Kind = "ok"
	KindSlow        Kind = "slow"
	KindDNSTamper   Kind = "dns_tamper"
	KindDNSFail     Kind = "dns_fail"
	KindIPBlock     Kind = "ip_block"
	KindSNIBlock    Kind = "sni_block"
	KindTLSFail     Kind = "tls_fail"
	KindBlockPage   Kind = "block_page"
	KindGeo         Kind = "geo"
	KindCutoff      Kind = "cutoff"
	KindStall       Kind = "stall"
	KindHTTPError   Kind = "http_error"
	KindUnreachable Kind = "unreachable"
)

// Bad reports whether the kind means the site does not work for the user.
func (k Kind) Bad() bool {
	return k != KindOK && k != KindSlow
}

// Step is one stage of a diagnosis, shown to the user as it completes.
type Step struct {
	Name string  `json:"name"`
	OK   bool    `json:"ok"`
	Text string  `json:"text"`
	Ms   float64 `json:"ms"`
}

type SiteResult struct {
	URL         string  `json:"url"`
	Host        string  `json:"host"`
	Kind        Kind    `json:"kind"`
	Text        string  `json:"text"`
	IP          string  `json:"ip"`
	Status      int     `json:"status"`
	Bytes       int64   `json:"bytes"`
	DNSms       float64 `json:"dns_ms"`
	ConnectMs   float64 `json:"connect_ms"`
	TLSms       float64 `json:"tls_ms"`
	TTFBms      float64 `json:"ttfb_ms"`
	TotalMs     float64 `json:"total_ms"`
	Mbps        float64 `json:"mbps"`
	CertTrusted bool    `json:"cert_trusted"`
	Steps       []Step  `json:"steps"`
}

type Options struct {
	// Download at least this many bytes; used by the cut-off test.
	MinBytes int64
	// Called after each step, for live output.
	OnStep func(Step)
}

// An honest agent: speed-test hosts drop browser agents that lack a browser TLS fingerprint.
const userAgent = "svyaz/1.0 (home network monitor)"

// Neutral name for the control handshake in the SNI test.
const controlSNI = "www.example.com"

var blockHostMarkers = []string{"warning.rt.ru", "zapret", "rkn.gov.ru", "blacklist", "blocked.", "/blocked", "eais."}

var blockBodyMarkers = []string{
	"роскомнадзор", "rkn.gov.ru", "доступ ограничен", "доступ к ресурсу ограничен",
	"единый реестр", "149-фз", "реестр запрещ", "заблокирован по решению",
}

var geoMarkers = []string{
	"unsupported_country", "not available in your country", "not available in your region",
	"unavailable in your country", "isn't available in your country", "is not available in your country",
	"not supported in your country", "supported in your country", "only available in certain regions",
	"country, region, or territory not supported", "not supported in your region", "unavailable in your region",
}

type run struct {
	opt   Options
	res   *SiteResult
	start time.Time
}

func (r *run) step(name string, ok bool, ms float64, format string, a ...any) {
	s := Step{Name: name, OK: ok, Text: fmt.Sprintf(format, a...), Ms: ms}
	r.res.Steps = append(r.res.Steps, s)
	if r.opt.OnStep != nil {
		r.opt.OnStep(s)
	}
}

func (r *run) finish(k Kind, format string, a ...any) *SiteResult {
	r.res.Kind = k
	r.res.Text = fmt.Sprintf(format, a...)
	r.res.TotalMs = ms(time.Since(r.start))
	return r.res
}

func ms(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }

// Diagnose walks DNS → TCP → TLS → HTTP for a URL and names the first stage
// that breaks.
func Diagnose(ctx context.Context, raw string, opt Options) *SiteResult {
	return diagnose(ctx, raw, opt, 0)
}

func diagnose(ctx context.Context, raw string, opt Options, depth int) *SiteResult {
	r := &run{opt: opt, res: &SiteResult{URL: raw}, start: time.Now()}
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return r.finish(KindUnreachable, "Не похоже на адрес сайта")
	}
	host := u.Hostname()
	r.res.Host = host
	port := u.Port()
	if port == "" {
		port = "443"
		if u.Scheme == "http" {
			port = "80"
		}
	}

	// DNS
	var sysIPs []net.IP
	var dnsDur time.Duration
	var sysErr error
	if ip := net.ParseIP(host); ip != nil {
		sysIPs = []net.IP{ip}
	} else {
		dctx, cancel := context.WithTimeout(ctx, 4*time.Second)
		sysIPs, dnsDur, sysErr = LookupSystem(dctx, host)
		cancel()
	}
	r.res.DNSms = ms(dnsDur)
	var refIPs []net.IP
	var refVia string
	var refErr error
	needRef := sysErr != nil || (suspicious(sysIPs) && net.ParseIP(host) == nil)
	if needRef {
		rctx, cancel := context.WithTimeout(ctx, 6*time.Second)
		refIPs, refVia, refErr = LookupReference(rctx, host)
		cancel()
	}
	ips := sysIPs
	var dnsKind Kind
	var dnsNote string
	switch {
	case net.ParseIP(host) != nil:
		r.step("DNS", true, 0, "Адрес указан напрямую, DNS не нужен")
	case sysErr == nil && !suspicious(sysIPs):
		r.step("DNS", true, r.res.DNSms, "%s → %s", host, joinIPs(sysIPs))
	case refErr == nil && len(refIPs) > 0:
		ips = refIPs
		dnsKind = KindDNSTamper
		if errors.Is(sysErr, ErrNXDomain) {
			dnsNote = fmt.Sprintf("Системный DNS говорит, что домена нет, а %s знает адрес %s", refVia, joinIPs(refIPs))
		} else if sysErr != nil {
			dnsKind = KindDNSFail
			dnsNote = fmt.Sprintf("Системный DNS не ответил (%s), адрес взят у %s", shortErr(sysErr), refVia)
		} else {
			dnsNote = fmt.Sprintf("Системный DNS отдал %s вместо %s", joinIPs(sysIPs), joinIPs(refIPs))
		}
		r.step("DNS", false, r.res.DNSms, "%s", dnsNote)
	case errors.Is(sysErr, ErrNXDomain) && errors.Is(refErr, ErrNXDomain):
		r.step("DNS", false, r.res.DNSms, "Такого домена нет")
		return r.finish(KindUnreachable, "Такого домена не существует")
	default:
		r.step("DNS", false, r.res.DNSms, "Адрес не получен: %s", shortErr(firstErr(sysErr, refErr)))
		return r.finish(KindDNSFail, "Не удалось узнать адрес сайта: DNS не отвечает")
	}

	// TCP
	var conn net.Conn
	var tcpErr error
	for i, ip := range ips {
		if i >= 2 {
			break
		}
		t0 := time.Now()
		d := net.Dialer{Timeout: 5 * time.Second}
		conn, tcpErr = d.DialContext(ctx, "tcp4", net.JoinHostPort(ip.String(), port))
		if tcpErr == nil {
			r.res.IP = ip.String()
			r.res.ConnectMs = ms(time.Since(t0))
			break
		}
	}
	if conn == nil {
		r.step("TCP", false, 0, "Соединение с %s:%s не установлено: %s", ips[0], port, describeNetErr(tcpErr))
		if isRefused(tcpErr) {
			return r.finish(KindUnreachable, "Сервер отклоняет соединения")
		}
		return r.finish(KindIPBlock, "Нет соединения с адресом сайта: %s", describeNetErr(tcpErr))
	}
	r.step("TCP", true, r.res.ConnectMs, "Соединение с %s:%s", r.res.IP, port)
	counted := &countConn{Conn: conn}
	defer counted.Close()
	var stream net.Conn = counted

	// TLS
	if u.Scheme != "http" {
		var trusted bool
		cfg := &tls.Config{
			ServerName:         host,
			InsecureSkipVerify: true,
			NextProtos:         []string{"http/1.1"},
			VerifyConnection: func(cs tls.ConnectionState) error {
				trusted = verifyChain(cs, host)
				return nil
			},
		}
		tc := tls.Client(counted, cfg)
		counted.SetDeadline(time.Now().Add(7 * time.Second))
		t0 := time.Now()
		err := tc.HandshakeContext(ctx)
		if err != nil {
			why := describeNetErr(err)
			ctrlOK := controlHandshake(ctx, r.res.IP, port)
			if ctrlOK {
				r.step("TLS", false, ms(time.Since(t0)), "С именем %s рукопожатие обрывается (%s), с другим именем на тот же адрес проходит", host, why)
				return r.finish(KindSNIBlock, "Соединение рвётся по имени сайта в TLS: блокировка по SNI")
			}
			r.step("TLS", false, ms(time.Since(t0)), "Рукопожатие не прошло ни с каким именем: %s", why)
			return r.finish(KindTLSFail, "TLS не устанавливается: %s", why)
		}
		r.res.TLSms = ms(time.Since(t0))
		r.res.CertTrusted = trusted
		note := ""
		if !trusted {
			note = ", сертификат не прошёл проверку"
		}
		r.step("TLS", true, r.res.TLSms, "Рукопожатие %s%s", tlsVersion(tc.ConnectionState().Version), note)
		stream = tc
	} else {
		r.res.CertTrusted = true
	}

	// HTTP
	path := u.RequestURI()
	req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nAccept: text/html,*/*\r\nAccept-Language: ru,en;q=0.8\r\nConnection: close\r\n", path, u.Host, userAgent)
	if opt.MinBytes > 0 {
		req += fmt.Sprintf("Range: bytes=0-%d\r\n", opt.MinBytes-1)
	}
	req += "\r\n"
	counted.SetDeadline(time.Now().Add(10 * time.Second))
	t0 := time.Now()
	if _, err := io.WriteString(stream, req); err != nil {
		r.step("HTTP", false, 0, "Запрос не отправлен: %s", describeNetErr(err))
		return r.finish(KindStall, "Соединение оборвалось при отправке запроса")
	}
	br := bufio.NewReaderSize(stream, 32<<10)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		r.step("HTTP", false, ms(time.Since(t0)), "Ответа нет: %s, получено %s", describeNetErr(err), kb(counted.n.Load()))
		if isTimeout(err) && inCutoffWindow(counted.n.Load()) {
			return r.finish(KindCutoff, "Соединение замирает после %s, не дождавшись ответа", kb(counted.n.Load()))
		}
		return r.finish(KindStall, "Сервер принял соединение, но не ответил: %s", describeNetErr(err))
	}
	defer resp.Body.Close()
	r.res.TTFBms = ms(time.Since(t0))
	r.res.Status = resp.StatusCode

	// Body: read until EOF, the limit, or a stall.
	limit := int64(128 << 10)
	if opt.MinBytes > 0 {
		limit = opt.MinBytes
	}
	var body []byte
	buf := make([]byte, 16<<10)
	stalled := false
	bodyStart := time.Now()
	for int64(len(body)) < limit {
		counted.SetDeadline(time.Now().Add(5 * time.Second))
		n, err := resp.Body.Read(buf)
		body = append(body, buf[:n]...)
		if err != nil {
			stalled = err != io.EOF && !errors.Is(err, io.ErrUnexpectedEOF)
			if errors.Is(err, io.ErrUnexpectedEOF) {
				stalled = true
			}
			break
		}
	}
	r.res.Bytes = int64(len(body))
	if el := time.Since(bodyStart); el > 0 && len(body) > 32<<10 {
		r.res.Mbps = float64(len(body)) * 8 / el.Seconds() / 1e6
	}
	wire := counted.n.Load()
	if stalled {
		r.step("Загрузка", false, ms(time.Since(t0)), "Загрузка встала на %s (всего по соединению %s)", kb(int64(len(body))), kb(wire))
		if inCutoffWindow(wire) {
			return r.finish(KindCutoff, "Соединение замирает после %s: так работает ограничение на зарубежные хостинги", kb(wire))
		}
		return r.finish(KindStall, "Загрузка останавливается на %s", kb(wire))
	}
	r.step("HTTP", true, r.res.TTFBms, "Ответ %d, получено %s", resp.StatusCode, kb(int64(len(body))))

	lower := strings.ToLower(string(body))
	loc := resp.Header.Get("Location")
	if hasAny(strings.ToLower(loc), blockHostMarkers) || resp.StatusCode == 451 || hasAny(lower, blockBodyMarkers) {
		if dnsKind == KindDNSTamper || (sysErr == nil && !refOverlap(ctx, host, sysIPs)) {
			return r.finish(KindDNSTamper, "DNS провайдера ведёт на страницу-заглушку о блокировке")
		}
		return r.finish(KindBlockPage, "Провайдер показывает страницу о блокировке")
	}
	if hasAny(lower, geoMarkers) {
		return r.finish(KindGeo, "Сервис сам не обслуживает пользователей из этого региона (ответ %d)", resp.StatusCode)
	}
	if resp.StatusCode >= 300 && resp.StatusCode < 400 && loc != "" && depth < 3 {
		next, err := u.Parse(loc)
		if err == nil && next.String() != raw {
			sub := diagnose(ctx, next.String(), opt, depth+1)
			sub.Steps = append(r.res.Steps, sub.Steps...)
			sub.URL = raw
			if dnsKind != "" && !sub.Kind.Bad() {
				sub.Kind, sub.Text = dnsKind, dnsNote
			}
			return sub
		}
	}
	if opt.MinBytes > 0 && int64(len(body)) < opt.MinBytes/2 && resp.StatusCode < 300 {
		return r.finish(KindStall, "Файл отдан не полностью: %s", kb(int64(len(body))))
	}
	if resp.StatusCode >= 500 {
		return r.finish(KindHTTPError, "Сервер отвечает ошибкой %d", resp.StatusCode)
	}
	if dnsKind != "" {
		return r.finish(dnsKind, "%s. По верному адресу сайт открывается", dnsNote)
	}
	if r.res.TTFBms > 3000 {
		return r.finish(KindSlow, "Открывается, но первый ответ пришёл через %.1f с", r.res.TTFBms/1000)
	}
	return r.finish(KindOK, "Открывается")
}

// controlHandshake checks whether the same address completes TLS for a
// neutral name. A TLS alert also counts: the server answered.
func controlHandshake(ctx context.Context, ip, port string) bool {
	d := net.Dialer{Timeout: 5 * time.Second}
	c, err := d.DialContext(ctx, "tcp4", net.JoinHostPort(ip, port))
	if err != nil {
		return false
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(6 * time.Second))
	tc := tls.Client(c, &tls.Config{ServerName: controlSNI, InsecureSkipVerify: true})
	err = tc.HandshakeContext(ctx)
	if err == nil {
		return true
	}
	var alert tls.AlertError
	return errors.As(err, &alert) || strings.Contains(err.Error(), "remote error")
}

func refOverlap(ctx context.Context, host string, sys []net.IP) bool {
	rctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	ref, _, err := LookupReference(rctx, host)
	if err != nil {
		return true // cannot tell; do not accuse DNS
	}
	return overlap(ref, sys)
}

func verifyChain(cs tls.ConnectionState, host string) bool {
	if len(cs.PeerCertificates) == 0 {
		return false
	}
	inter := x509.NewCertPool()
	for _, c := range cs.PeerCertificates[1:] {
		inter.AddCert(c)
	}
	_, err := cs.PeerCertificates[0].Verify(x509.VerifyOptions{DNSName: host, Intermediates: inter})
	return err == nil
}

type countConn struct {
	net.Conn
	n atomic.Int64
}

func (c *countConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	c.n.Add(int64(n))
	return n, err
}

// The cut-off on foreign hosting lets roughly 14–24 KB through; allow margin.
func inCutoffWindow(n int64) bool { return n >= 10<<10 && n <= 40<<10 }

func kb(n int64) string {
	if n < 1024 {
		return fmt.Sprintf("%d Б", n)
	}
	return fmt.Sprintf("%d КБ", (n+512)/1024)
}

func joinIPs(ips []net.IP) string {
	var s []string
	for i, ip := range ips {
		if i == 3 {
			s = append(s, "…")
			break
		}
		s = append(s, ip.String())
	}
	return strings.Join(s, ", ")
}

func hasAny(s string, subs []string) bool {
	for _, x := range subs {
		if strings.Contains(s, x) {
			return true
		}
	}
	return false
}

func firstErr(errs ...error) error {
	for _, e := range errs {
		if e != nil {
			return e
		}
	}
	return errors.New("неизвестная ошибка")
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout() || errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, context.DeadlineExceeded)
}

func isRefused(err error) bool { return errors.Is(err, syscall.ECONNREFUSED) }

// describeNetErr turns a network error into a short Russian phrase.
func describeNetErr(err error) string {
	switch {
	case err == nil:
		return "без ошибки"
	case isTimeout(err):
		return "нет ответа (таймаут)"
	case errors.Is(err, syscall.ECONNRESET):
		return "соединение сброшено"
	case errors.Is(err, syscall.ECONNREFUSED):
		return "в соединении отказано"
	case errors.Is(err, syscall.EHOSTUNREACH), errors.Is(err, syscall.ENETUNREACH):
		return "адрес недостижим"
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return "соединение закрыто"
	}
	return shortErr(err)
}

func shortErr(err error) string {
	if err == nil {
		return ""
	}
	if isTimeout(err) {
		return "таймаут"
	}
	if errors.Is(err, ErrNXDomain) {
		return "домен не найден"
	}
	s := err.Error()
	if i := strings.LastIndex(s, ": "); i >= 0 && i+2 < len(s) {
		s = s[i+2:]
	}
	return s
}

func tlsVersion(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionTLS12:
		return "TLS 1.2"
	}
	return "TLS"
}
