// Package web serves the dashboard.
package web

import (
	"bytes"
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/antoniocra04/network/internal/config"
	"github.com/antoniocra04/network/internal/monitor"
	"github.com/antoniocra04/network/internal/probe"
	"github.com/antoniocra04/network/internal/store"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static
var staticFS embed.FS

type Server struct {
	mon   *monitor.Monitor
	store *store.Store
	cfg   *config.Config
	pages map[string]*template.Template
}

var pageNames = []string{"overview", "services", "quality", "journal", "incident", "check"}

// assetVersion changes whenever the embedded static files change, so
// long-cached assets are refetched after an update.
var assetVersion = func() string {
	h := sha256.New()
	fs.WalkDir(staticFS, "static", func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			b, _ := staticFS.ReadFile(p)
			h.Write(b)
		}
		return nil
	})
	return hex.EncodeToString(h.Sum(nil))[:10]
}()

func New(mon *monitor.Monitor, st *store.Store, cfg *config.Config) (*Server, error) {
	s := &Server{mon: mon, store: st, cfg: cfg, pages: map[string]*template.Template{}}
	funcs["asset"] = func(name string) string { return "/static/" + name + "?v=" + assetVersion }
	for _, p := range pageNames {
		t, err := template.New("").Funcs(funcs).ParseFS(templateFS, "templates/layout.html", "templates/parts.html", "templates/"+p+".html")
		if err != nil {
			return nil, fmt.Errorf("template %s: %w", p, err)
		}
		s.pages[p] = t
	}
	return s, nil
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	static, _ := fs.Sub(staticFS, "static")
	mux.Handle("GET /static/", http.StripPrefix("/static/", cacheFor(http.FileServerFS(static), 30*24*time.Hour)))
	mux.HandleFunc("GET /{$}", s.overview)
	mux.HandleFunc("GET /services", s.services)
	mux.HandleFunc("GET /quality", s.quality)
	mux.HandleFunc("GET /journal", s.journal)
	mux.HandleFunc("GET /journal/{id}", s.incident)
	mux.HandleFunc("GET /check", s.check)
	mux.HandleFunc("GET /check/run", s.checkRun)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })
	return mux
}

func cacheFor(h http.Handler, d time.Duration) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", fmt.Sprintf("public, max-age=%d", int(d.Seconds())))
		h.ServeHTTP(w, r)
	})
}

// render executes the page, or just one block when HTMX asks for a part.
func (s *Server) render(w http.ResponseWriter, r *http.Request, page string, data any) {
	name := "layout"
	if part := r.URL.Query().Get("part"); part != "" && r.Header.Get("HX-Request") == "true" {
		name = part
	}
	var buf bytes.Buffer
	if err := s.pages[page].ExecuteTemplate(&buf, name, data); err != nil {
		log.Printf("render %s/%s: %v", page, name, err)
		http.Error(w, "Ошибка шаблона", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Write(buf.Bytes())
}

type base struct {
	Page  string
	Title string
	S     monitor.State
}

type tlRow struct {
	Name  string
	Layer string
	SVG   template.HTML
}

func (s *Server) timeline(now time.Time) ([]tlRow, []string) {
	bucket := 5 * time.Minute
	to := now.Truncate(bucket).Add(bucket)
	from := to.Add(-24 * time.Hour)
	snaps, err := s.store.Snapshots(from, to)
	if err != nil {
		log.Printf("snapshots: %v", err)
	}
	var rows []tlRow
	for _, l := range []config.Layer{config.LayerHome, config.LayerISP, config.LayerRunet, config.LayerBorder, config.LayerForeign} {
		rows = append(rows, tlRow{Name: monitor.LayerNames[l], Layer: string(l), SVG: timelineRow(snaps, string(l), from, to, bucket)})
	}
	var ticks []string
	for i := 0; i <= 4; i++ {
		ticks = append(ticks, from.Add(time.Duration(i)*6*time.Hour).Local().Format("15:04"))
	}
	return rows, ticks
}

func (s *Server) overview(w http.ResponseWriter, r *http.Request) {
	st := s.mon.State()
	rows, ticks := s.timeline(time.Now())
	incs, _ := s.store.Incidents(time.Now().Add(-24*time.Hour), 8)
	var problems []monitor.CheckView
	for _, v := range st.Services {
		if v.Status >= store.Warn {
			problems = append(problems, v)
		}
	}
	s.render(w, r, "overview", struct {
		base
		Timeline  []tlRow
		Ticks     []string
		Incidents []store.Incident
		Problems  []monitor.CheckView
	}{base{"overview", "Обзор", st}, rows, ticks, incs, problems})
}

type svcGroup struct {
	Name  string
	Items []monitor.CheckView
}

func (s *Server) services(w http.ResponseWriter, r *http.Request) {
	st := s.mon.State()
	var groups []svcGroup
	idx := map[string]int{}
	for _, v := range st.Services {
		i, ok := idx[v.Group]
		if !ok {
			i = len(groups)
			idx[v.Group] = i
			groups = append(groups, svcGroup{Name: v.Group})
		}
		groups[i].Items = append(groups[i].Items, v)
	}
	var segments []monitor.LayerView
	for _, l := range []string{"runet", "foreign", "border"} {
		segments = append(segments, st.Layer(l))
	}
	s.render(w, r, "services", struct {
		base
		Groups   []svcGroup
		Segments []monitor.LayerView
	}{base{"services", "Сервисы", st}, groups, segments})
}

type chartPanel struct {
	Title  string
	Note   string
	Legend []chartSeries
	SVG    template.HTML
}

var ranges = []struct {
	Key    string
	Label  string
	Span   time.Duration
	Bucket time.Duration
}{
	{"6h", "6 часов", 6 * time.Hour, 2 * time.Minute},
	{"24h", "24 часа", 24 * time.Hour, 10 * time.Minute},
	{"7d", "7 дней", 7 * 24 * time.Hour, time.Hour},
}

func (s *Server) quality(w http.ResponseWriter, r *http.Request) {
	st := s.mon.State()
	rk := r.URL.Query().Get("range")
	rg := ranges[1]
	for _, x := range ranges {
		if x.Key == rk {
			rg = x
		}
	}
	now := time.Now()
	to := now.Truncate(rg.Bucket).Add(rg.Bucket)
	from := to.Add(-rg.Span)
	groups := []struct {
		title, note string
		layers      []config.Layer
	}{
		{"Дом и провайдер", "Роутер и первый узел провайдера. Рост здесь — проблема до выхода в интернет.", []config.Layer{config.LayerHome, config.LayerISP}},
		{"Рунет", "Российские узлы.", []config.Layer{config.LayerRunet}},
		{"Зарубеж", "Зарубежные узлы. Сравни с Рунетом: разница показывает, сколько добавляет внешний канал.", []config.Layer{config.LayerForeign}},
	}
	var panels []chartPanel
	for _, g := range groups {
		var series []chartSeries
		for _, c := range s.mon.Checks() {
			if c.Type != monitor.TypePing || !hasLayer(g.layers, c.Layer) || len(series) >= len(seriesColors) {
				continue
			}
			pts, err := s.store.Series(c.ID, from, rg.Bucket)
			if err != nil {
				log.Printf("series: %v", err)
			}
			series = append(series, chartSeries{Name: c.Name, Color: seriesColors[len(series)], Points: pts})
		}
		panels = append(panels, chartPanel{Title: g.title, Note: g.note, Legend: series, SVG: latencyChart(series, from, to, rg.Bucket)})
	}
	var throttle []monitor.CheckView
	for _, c := range st.Layer("border").Checks {
		throttle = append(throttle, c)
	}
	s.render(w, r, "quality", struct {
		base
		Range    string
		Ranges   any
		Panels   []chartPanel
		Throttle []monitor.CheckView
	}{base{"quality", "Качество", st}, rg.Key, ranges, panels, throttle})
}

func hasLayer(ls []config.Layer, l config.Layer) bool {
	for _, x := range ls {
		if x == l {
			return true
		}
	}
	return false
}

func (s *Server) journal(w http.ResponseWriter, r *http.Request) {
	st := s.mon.State()
	now := time.Now()
	incs, err := s.store.Incidents(now.AddDate(0, 0, -90), 300)
	if err != nil {
		log.Printf("incidents: %v", err)
	}
	var open, closed []store.Incident
	for _, in := range incs {
		if in.Open() {
			open = append(open, in)
		} else {
			closed = append(closed, in)
		}
	}
	days, err := s.store.Days(now.AddDate(0, 0, -7*13-7), time.Local)
	if err != nil {
		log.Printf("days: %v", err)
	}
	boots, _ := s.store.Boots(now.AddDate(0, 0, -30))
	s.render(w, r, "journal", struct {
		base
		Open     []store.Incident
		Closed   []store.Incident
		Calendar []calDay
		Boots    []time.Time
	}{base{"journal", "Журнал", st}, open, closed, calendarDays(days, now), boots})
}

func (s *Server) incident(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	in, err := s.store.Incident(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	items := monitor.ParseSnapshot(in.Snapshot)
	sort.SliceStable(items, func(i, j int) bool { return items[i].Status > items[j].Status })
	s.render(w, r, "incident", struct {
		base
		Inc   store.Incident
		Items []monitor.SnapshotItem
	}{base{"journal", in.Title, s.mon.State()}, in, items})
}

func (s *Server) check(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "check", struct {
		base
		Domain string
	}{base{"check", "Проверить сайт", s.mon.State()}, r.URL.Query().Get("d")})
}

// normalize turns "telegram.org" or a pasted link into an https URL.
func normalize(in string) (string, bool) {
	in = strings.TrimSpace(in)
	if in == "" {
		return "", false
	}
	if !strings.Contains(in, "://") {
		in = "https://" + in
	}
	u, err := url.Parse(in)
	if err != nil || u.Hostname() == "" || !strings.Contains(u.Hostname(), ".") {
		return "", false
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", false
	}
	if u.Path == "" {
		u.Path = "/"
	}
	return u.String(), true
}

// checkRun streams each diagnosis step as a server-sent event.
func (s *Server) checkRun(w http.ResponseWriter, r *http.Request) {
	fl, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	t := s.pages["check"]
	send := func(event, block string, data any) {
		var buf bytes.Buffer
		if err := t.ExecuteTemplate(&buf, block, data); err != nil {
			log.Printf("sse %s: %v", block, err)
			return
		}
		fmt.Fprintf(w, "event: %s\n", event)
		for _, line := range strings.Split(strings.TrimRight(buf.String(), "\n"), "\n") {
			fmt.Fprintf(w, "data: %s\n", line)
		}
		fmt.Fprint(w, "\n")
		fl.Flush()
	}
	target, ok := normalize(r.URL.Query().Get("d"))
	if !ok {
		send("done", "check-invalid", nil)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	res := probe.Diagnose(ctx, target, probe.Options{OnStep: func(st probe.Step) { send("step", "check-step", st) }})
	status := store.OK
	switch {
	case res.Kind == probe.KindSlow, res.Kind == probe.KindCutoff, res.Kind == probe.KindStall:
		status = store.Warn
	case res.Kind.Bad():
		status = store.Fail
	}
	send("done", "check-result", struct {
		R      *probe.SiteResult
		Status store.Status
	}{res, status})
}
