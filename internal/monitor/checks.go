package monitor

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/antoniocra04/network/internal/config"
	"github.com/antoniocra04/network/internal/probe"
	"github.com/antoniocra04/network/internal/store"
)

// CheckType says how a check is run and rendered.
type CheckType string

const (
	TypePing     CheckType = "ping"
	TypeSite     CheckType = "site"
	TypeThrottle CheckType = "throttle"
	TypeDNS      CheckType = "dns"
)

type Check struct {
	ID       string
	Name     string
	Layer    config.Layer
	Type     CheckType
	Target   string
	Interval time.Duration
	run      func(ctx context.Context) Result
}

// Result is the latest outcome of a check.
type Result struct {
	CheckID string
	At      time.Time
	Status  store.Status
	Value   float64 // milliseconds; 0 when not applicable
	Loss    float64 // ping loss, 0..1
	Kind    string  // probe.Kind for sites, "ping"/"dns" otherwise
	Summary string  // one short line for the UI
	Site    *probe.SiteResult
	Since   time.Time // when this status and kind began
}

// Latency limits per layer for a ping to count as degraded.
var slowPing = map[config.Layer]time.Duration{
	config.LayerHome:    30 * time.Millisecond,
	config.LayerISP:     60 * time.Millisecond,
	config.LayerRunet:   150 * time.Millisecond,
	config.LayerForeign: 400 * time.Millisecond,
}

func (m *Monitor) buildChecks() {
	iv := m.cfg.Intervals
	add := func(c *Check) { m.checks = append(m.checks, c) }

	add(&Check{ID: "gateway", Name: "Роутер", Layer: config.LayerHome, Type: TypePing, Interval: iv.Ping,
		run: func(ctx context.Context) Result {
			gw := m.gatewayIP()
			if gw == nil {
				return Result{Status: store.Unknown, Kind: "ping", Summary: "Адрес роутера не найден: нет маршрута по умолчанию"}
			}
			return m.pingResult(ctx, gw.String(), config.LayerHome)
		}})
	add(&Check{ID: "isp-hop", Name: "Узел провайдера", Layer: config.LayerISP, Type: TypePing, Interval: iv.Ping,
		run: func(ctx context.Context) Result {
			hop := m.ispHopIP()
			if hop == nil {
				return Result{Status: store.Unknown, Kind: "ping", Summary: "Первый узел провайдера ещё не найден"}
			}
			return m.pingResult(ctx, hop.String(), config.LayerISP)
		}})
	add(&Check{ID: "dns-system", Name: "DNS роутера/провайдера", Layer: config.LayerISP, Type: TypeDNS, Interval: iv.Ping,
		run: func(ctx context.Context) Result {
			ips, d, err := probe.LookupSystem(ctx, "ya.ru")
			if err != nil {
				return Result{Status: store.Fail, Kind: "dns", Summary: "Системный DNS не отвечает: " + errText(err)}
			}
			r := Result{Status: store.OK, Kind: "dns", Value: msf(d), Summary: fmt.Sprintf("ya.ru → %s", ips[0])}
			if d > 500*time.Millisecond {
				r.Status = store.Warn
				r.Summary = fmt.Sprintf("Отвечает медленно: %d мс", d.Milliseconds())
			}
			return r
		}})

	for _, a := range m.cfg.Anchors {
		a := a
		add(&Check{ID: a.ID, Name: a.Name, Layer: a.Layer, Type: TypePing, Target: a.Host, Interval: iv.Ping,
			run: func(ctx context.Context) Result { return m.pingResult(ctx, a.Host, a.Layer) }})
	}
	for _, s := range m.cfg.Sites {
		s := s
		add(&Check{ID: s.ID, Name: s.Name, Layer: s.Layer, Type: TypeSite, Target: s.URL, Interval: iv.Sites,
			run: func(ctx context.Context) Result { return siteResult(ctx, s.URL, probe.Options{}) }})
	}
	for _, t := range m.cfg.Throttle {
		t := t
		add(&Check{ID: t.ID, Name: t.Name, Layer: config.LayerBorder, Type: TypeThrottle, Target: t.URL, Interval: iv.Throttle,
			run: func(ctx context.Context) Result {
				r := siteResult(ctx, t.URL, probe.Options{MinBytes: 128 << 10})
				if r.Site != nil && r.Site.Kind == probe.KindOK {
					r.Summary = fmt.Sprintf("128 КБ загружены, %.1f Мбит/с", r.Site.Mbps)
					r.Value = r.Site.Mbps
				}
				return r
			}})
	}
	add(&Check{ID: "dns-udp-foreign", Name: "DNS 8.8.8.8 по UDP", Layer: config.LayerBorder, Type: TypeDNS, Target: "8.8.8.8", Interval: iv.Sites,
		run: func(ctx context.Context) Result {
			ips, d, err := probe.QueryUDP(ctx, "8.8.8.8", "www.wikipedia.org")
			if err != nil {
				return Result{Status: store.Warn, Kind: "dns", Summary: "Запросы к зарубежному DNS по UDP/53 не проходят: " + errText(err)}
			}
			// Same resolver over DoH: a different answer means the UDP reply
			// was forged on the way.
			ref, rerr := probe.LookupDoHVia(ctx, "Google", "www.wikipedia.org")
			if rerr == nil && !sameNet(ips, ref) {
				return Result{Status: store.Warn, Kind: "dns", Value: msf(d),
					Summary: fmt.Sprintf("По UDP 8.8.8.8 ответил %s, а по DoH тот же Google — %s: ответы подменяются по пути", ips[0], ref[0])}
			}
			return Result{Status: store.OK, Kind: "dns", Value: msf(d), Summary: fmt.Sprintf("Отвечает за %d мс, ответ совпадает с зашифрованным DNS", d.Milliseconds())}
		}})
	add(&Check{ID: "doh", Name: "Зашифрованный DNS", Layer: config.LayerBorder, Type: TypeDNS, Interval: iv.Sites,
		run: func(ctx context.Context) Result {
			res := probe.DoHAvailable(ctx)
			var bad []string
			for _, n := range []string{"Cloudflare", "Google", "Яндекс"} {
				if res[n] != nil {
					bad = append(bad, n)
				}
			}
			switch len(bad) {
			case 0:
				return Result{Status: store.OK, Kind: "dns", Summary: "Cloudflare, Google и Яндекс отвечают по DoH"}
			case len(res):
				return Result{Status: store.Warn, Kind: "dns", Summary: "Ни один DoH-сервер не отвечает"}
			}
			return Result{Status: store.Warn, Kind: "dns", Summary: "Не отвечают по DoH: " + joinRu(bad)}
		}})
}

func (m *Monitor) pingResult(ctx context.Context, host string, layer config.Layer) Result {
	st, err := m.pinger.Ping(ctx, host, 4, 200*time.Millisecond, 2*time.Second)
	if err != nil && st.Sent == 0 {
		if errors.Is(err, probe.ErrNoICMP) {
			return Result{Status: store.Unknown, Kind: "ping", Summary: "ICMP недоступен: контейнеру нужен NET_RAW"}
		}
		return Result{Status: store.Fail, Kind: "ping", Loss: 1, Summary: errText(err)}
	}
	r := Result{Kind: "ping", Loss: st.Loss(), Value: msf(st.Avg)}
	switch {
	case st.Recv == 0:
		r.Status = store.Fail
		r.Summary = fmt.Sprintf("Не отвечает: потеряно %d из %d", st.Sent, st.Sent)
	case st.Loss() >= 0.5:
		r.Status = store.Warn
		r.Summary = fmt.Sprintf("Потери %.0f%%, %.1f мс", st.Loss()*100, msf(st.Avg))
	case st.Avg > slowPing[layer]:
		r.Status = store.Warn
		r.Summary = fmt.Sprintf("Медленно: %.0f мс, разброс %.0f мс", msf(st.Avg), msf(st.Jitter))
	default:
		r.Status = store.OK
		r.Summary = fmt.Sprintf("%.1f мс, разброс %.1f мс", msf(st.Avg), msf(st.Jitter))
		if st.Loss() > 0 {
			r.Summary += fmt.Sprintf(", потеряно %d из %d", st.Sent-st.Recv, st.Sent)
		}
	}
	return r
}

func siteResult(ctx context.Context, url string, opt probe.Options) Result {
	s := probe.Diagnose(ctx, url, opt)
	r := Result{Kind: string(s.Kind), Summary: s.Text, Site: s, Value: s.ConnectMs}
	switch {
	case s.Kind == probe.KindOK:
		r.Status = store.OK
	case s.Kind == probe.KindSlow:
		r.Status = store.Warn
	case s.Kind == probe.KindCutoff || s.Kind == probe.KindStall:
		r.Status = store.Warn
	default:
		r.Status = store.Fail
	}
	return r
}

func msf(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }

func errText(err error) string {
	var de *net.DNSError
	switch {
	case errors.As(err, &de) && de.IsTimeout, errors.Is(err, context.DeadlineExceeded):
		return "нет ответа"
	case errors.Is(err, probe.ErrNXDomain):
		return "домен не найден"
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return "нет ответа"
	}
	return err.Error()
}

// sameNet treats answers as matching when they share a /24: CDNs rotate
// addresses inside the same block.
func sameNet(a, b []net.IP) bool {
	for _, x := range a {
		for _, y := range b {
			x4, y4 := x.To4(), y.To4()
			if x4 != nil && y4 != nil && x4[0] == y4[0] && x4[1] == y4[1] && x4[2] == y4[2] {
				return true
			}
		}
	}
	return false
}

func joinRu(items []string) string {
	switch len(items) {
	case 0:
		return ""
	case 1:
		return items[0]
	}
	out := items[0]
	for _, s := range items[1 : len(items)-1] {
		out += ", " + s
	}
	return out + " и " + items[len(items)-1]
}
