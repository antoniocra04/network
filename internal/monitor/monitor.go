// Package monitor runs the checks on schedule and turns their results into
// layer states, a verdict and incidents.
package monitor

import (
	"context"
	"encoding/json"
	"log"
	"math/rand/v2"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/antoniocra04/network/internal/config"
	"github.com/antoniocra04/network/internal/probe"
	"github.com/antoniocra04/network/internal/store"
)

type Monitor struct {
	cfg    *config.Config
	store  *store.Store
	pinger *probe.Pinger
	checks []*Check
	sem    chan struct{}

	mu        sync.RWMutex
	results   map[string]*Result
	gateway   net.IP
	ispHop    net.IP
	pub       probe.PublicIP
	ruIP      string
	ipSince   time.Time
	pending   []store.Sample
	state     State
	started   time.Time
	downSince time.Time // last snapshot before this boot; Pi was off after it

	layerStatus map[config.Layer]store.Status
	layerSince  map[config.Layer]time.Time
	inc         map[string]*incTrack
	base        map[string]*baseline
}

type incTrack struct {
	id      int64
	bad, ok int
	lastBad time.Time
}

func New(cfg *config.Config, st *store.Store) *Monitor {
	m := &Monitor{
		cfg:         cfg,
		store:       st,
		pinger:      probe.NewPinger(),
		sem:         make(chan struct{}, 6),
		results:     map[string]*Result{},
		layerStatus: map[config.Layer]store.Status{},
		layerSince:  map[config.Layer]time.Time{},
		inc:         map[string]*incTrack{},
		base:        map[string]*baseline{},
	}
	m.buildChecks()
	m.started = time.Now()
	m.state = m.compute(m.started)
	if !m.pinger.Available() {
		log.Print("ICMP недоступен: пинги работать не будут (нужен root или CAP_NET_RAW)")
	}
	return m
}

func (m *Monitor) Checks() []*Check { return m.checks }

func (m *Monitor) gatewayIP() net.IP {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.gateway
}

func (m *Monitor) ispHopIP() net.IP {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.ispHop
}

// Run starts all loops and blocks until ctx is done.
func (m *Monitor) Run(ctx context.Context) {
	now := time.Now()
	last, err := m.store.RecordBoot(now)
	if err != nil {
		log.Printf("boot: %v", err)
	}
	m.downSince = last
	if !last.IsZero() {
		m.store.CloseAllOpen(last)
	}
	m.pub.IP = m.store.KV("public_ip")
	m.pub.Org = m.store.KV("public_org")
	m.pub.City = m.store.KV("public_city")
	if t, err := time.Parse(time.RFC3339, m.store.KV("public_ip_since")); err == nil {
		m.ipSince = t
	}

	// The gateway is needed by the first ping; the ISP hop search is slow
	// and runs in its own loop below.
	if gw, err := probe.DefaultGateway(); err == nil {
		m.mu.Lock()
		m.gateway = gw
		m.mu.Unlock()
	}
	var wg sync.WaitGroup
	loop := func(every time.Duration, f func()) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			f()
			t := time.NewTicker(every)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
					f()
				}
			}
		}()
	}
	for _, c := range m.checks {
		c := c
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Spread start so the first minute is not a burst.
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Duration(rand.IntN(3000)) * time.Millisecond):
			}
			m.runCheck(ctx, c)
			t := time.NewTicker(c.Interval)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
					m.runCheck(ctx, c)
				}
			}
		}()
	}
	loop(m.cfg.Intervals.Route, func() { m.refreshRoute(ctx) })
	loop(m.cfg.Intervals.PublicIP, func() { m.refreshPublicIP(ctx) })
	loop(m.cfg.Intervals.Ping, func() { m.tick(time.Now()) })
	loop(time.Hour, func() {
		if err := m.store.Prune(time.Now(), 14*24*time.Hour, 400*24*time.Hour); err != nil {
			log.Printf("prune: %v", err)
		}
	})
	wg.Wait()
}

func (m *Monitor) runCheck(ctx context.Context, c *Check) {
	if c.Type == TypeSite || c.Type == TypeService || c.Type == TypeThrottle {
		select {
		case m.sem <- struct{}{}:
			defer func() { <-m.sem }()
		case <-ctx.Done():
			return
		}
	}
	timeout := min(c.Interval, 45*time.Second)
	cctx, cancel := context.WithTimeout(ctx, timeout)
	r := c.run(cctx)
	cancel()
	if ctx.Err() != nil {
		return
	}
	r.CheckID = c.ID
	r.At = time.Now()

	m.mu.Lock()
	defer m.mu.Unlock()
	prev := m.results[c.ID]
	r.Since = r.At
	if prev != nil && prev.Status == r.Status && prev.Kind == r.Kind {
		r.Since = prev.Since
	}
	m.results[c.ID] = &r
	if c.Layer == config.LayerServices {
		m.observe(c.ID, &r)
	}
	if r.Status != store.Unknown {
		m.pending = append(m.pending, store.Sample{TS: r.At, CheckID: c.ID, Status: r.Status, Value: r.Value, Kind: r.Kind})
	}
}

func (m *Monitor) refreshRoute(ctx context.Context) {
	gw, err := probe.DefaultGateway()
	if err != nil {
		log.Printf("gateway: %v", err)
	}
	m.mu.Lock()
	m.gateway = gw
	m.mu.Unlock()
	if gw == nil {
		return
	}
	hctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	hop, _, err := probe.FindISPHop(hctx, m.pinger, gw)
	if err != nil {
		return // keep the previous hop
	}
	m.mu.Lock()
	m.ispHop = hop
	m.mu.Unlock()
}

func (m *Monitor) refreshPublicIP(ctx context.Context) {
	cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	ru, ruErr := probe.PublicIPRunet(cctx)
	pub, pubErr := probe.PublicIPForeign(cctx)
	m.mu.Lock()
	defer m.mu.Unlock()
	if ruErr == nil {
		m.ruIP = ru
	}
	ip := ru
	if pubErr == nil && pub.IP != "" {
		ip = pub.IP
		m.pub.Org, m.pub.City, m.pub.Country = pub.Org, pub.City, pub.Country
		m.store.SetKV("public_org", pub.Org)
		m.store.SetKV("public_city", pub.City)
	}
	if ip != "" && ip != m.pub.IP {
		m.pub.IP = ip
		m.ipSince = time.Now()
		m.store.SetKV("public_ip", ip)
		m.store.SetKV("public_ip_since", m.ipSince.Format(time.RFC3339))
	}
}

// tick recomputes the state, writes a snapshot and updates incidents.
func (m *Monitor) tick(now time.Time) {
	m.mu.Lock()
	st := m.compute(now)
	m.state = st
	samples := m.pending
	m.pending = nil
	m.mu.Unlock()

	if len(samples) > 0 {
		if err := m.store.AddSamples(samples); err != nil {
			log.Printf("samples: %v", err)
		}
	}
	if st.Warming {
		return
	}
	sn := store.Snapshot{TS: now, Headline: st.Headline, Layers: map[string]store.Status{}}
	for _, l := range st.Layers {
		sn.Layers[string(l.Layer)] = l.Status
	}
	if err := m.store.AddSnapshot(sn); err != nil {
		log.Printf("snapshot: %v", err)
	}
	m.trackIncidents(now, st)
}

// State returns the latest computed state.
func (m *Monitor) State() State {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.state
}

func (m *Monitor) Result(id string) (Result, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	r, ok := m.results[id]
	if !ok {
		return Result{}, false
	}
	return *r, true
}

func (m *Monitor) trackIncidents(now time.Time, st State) {
	type subj struct {
		key, layer, title, detail string
		sev                       store.Status
	}
	var bad []subj
	root := st.Root
	if root != "" {
		l := st.layer(root)
		bad = append(bad, subj{key: "layer:" + string(root), layer: string(root), title: st.Headline, detail: st.Detail, sev: l.Status})
	}
	// Border problems are their own story even when the route is fine.
	if b := st.layer(config.LayerBorder); b.Status >= store.Warn && root != config.LayerForeign && st.layer(config.LayerForeign).Status != store.Fail {
		bad = append(bad, subj{key: "layer:border", layer: "border", title: b.Detail, detail: "", sev: b.Status})
	}
	// Services only matter while the foreign segment itself works, and only
	// when they stop opening; a block that is the usual state is not news.
	if st.layer(config.LayerForeign).Status != store.Fail && root != config.LayerHome && root != config.LayerISP {
		for _, s := range st.Services {
			if s.Change == ChangeBroke {
				bad = append(bad, subj{key: "svc:" + s.ID, layer: "services", title: s.Name + ": " + kindTitle(s.Kind), detail: s.Summary, sev: s.Status})
			}
		}
	}

	seen := map[string]bool{}
	for _, b := range bad {
		seen[b.key] = true
		t := m.inc[b.key]
		if t == nil {
			t = &incTrack{}
			m.inc[b.key] = t
		}
		t.bad++
		t.ok = 0
		t.lastBad = now
		switch {
		case t.id == 0 && t.bad >= 2:
			id, err := m.store.OpenIncident(store.Incident{
				Layer: b.layer, Subject: b.key, Severity: b.sev, Title: b.title, Detail: b.detail,
				Started: now.Add(-m.cfg.Intervals.Ping), Snapshot: m.snapshotJSON(),
			})
			if err != nil {
				log.Printf("incident: %v", err)
				continue
			}
			t.id = id
		case t.id != 0:
			m.store.UpdateIncident(t.id, b.sev, b.title, b.detail)
		}
	}
	for key, t := range m.inc {
		if seen[key] {
			continue
		}
		t.bad = 0
		t.ok++
		if t.id != 0 && t.ok >= 4 {
			m.store.CloseIncident(t.id, t.lastBad)
			delete(m.inc, key)
		} else if t.id == 0 {
			delete(m.inc, key)
		}
	}
}

// snapshotJSON captures every check result when an incident opens.
func (m *Monitor) snapshotJSON() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	type item struct {
		ID      string       `json:"id"`
		Name    string       `json:"name"`
		Layer   string       `json:"layer"`
		Status  store.Status `json:"status"`
		Summary string       `json:"summary"`
		Steps   []probe.Step `json:"steps,omitempty"`
	}
	var out []item
	for _, c := range m.checks {
		r := m.results[c.ID]
		if r == nil {
			continue
		}
		it := item{ID: c.ID, Name: c.Name, Layer: string(c.Layer), Status: r.Status, Summary: r.Summary}
		if r.Site != nil && r.Status != store.OK {
			it.Steps = r.Site.Steps
		}
		out = append(out, it)
	}
	b, _ := json.Marshal(out)
	return string(b)
}

// SnapshotItem is one line of a stored incident snapshot.
type SnapshotItem struct {
	ID      string       `json:"id"`
	Name    string       `json:"name"`
	Layer   string       `json:"layer"`
	Status  store.Status `json:"status"`
	Summary string       `json:"summary"`
	Steps   []probe.Step `json:"steps"`
}

func ParseSnapshot(s string) []SnapshotItem {
	var out []SnapshotItem
	json.Unmarshal([]byte(s), &out)
	return out
}

func ispName(org string) string {
	// "AS8402 PJSC Vimpelcom" → "PJSC Vimpelcom"
	if strings.HasPrefix(org, "AS") {
		if _, rest, ok := strings.Cut(org, " "); ok {
			return rest
		}
	}
	return org
}

func asn(org string) string {
	if strings.HasPrefix(org, "AS") {
		a, _, _ := strings.Cut(org, " ")
		return a
	}
	return ""
}
