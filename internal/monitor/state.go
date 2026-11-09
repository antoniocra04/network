package monitor

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/antoniocra04/network/internal/config"
	"github.com/antoniocra04/network/internal/probe"
	"github.com/antoniocra04/network/internal/store"
)

type CheckView struct {
	ID      string
	Name    string
	Group   string
	Target  string
	Layer   config.Layer
	Type    CheckType
	Status  store.Status
	Kind    string
	Summary string
	Value   float64
	Loss    float64
	At      time.Time
	Since   time.Time
	Steps   []probe.Step
}

type LayerView struct {
	Layer   config.Layer
	Name    string
	Status  store.Status
	Since   time.Time
	Summary string // a few words under the layer name
	Detail  string
	Failed  int // checks in the layer that do not work at all
	Checks  []CheckView
}

type State struct {
	At        time.Time
	Warming   bool
	Headline  string
	Detail    string
	Severity  store.Status
	Since     time.Time
	Root      config.Layer // where the route first breaks, if anywhere
	Layers    []LayerView
	Services  []CheckView
	Gateway   string
	ISPHop    string
	PublicIP  string
	RuIP      string
	ISP       string
	ASN       string
	City      string
	IPSince   time.Time
	Started   time.Time
	DownSince time.Time
	Pi        PiInfo
}

func (s State) layer(l config.Layer) LayerView {
	for _, v := range s.Layers {
		if v.Layer == l {
			return v
		}
	}
	return LayerView{Layer: l}
}

// Layer returns the view of one layer.
func (s State) Layer(name string) LayerView { return s.layer(config.Layer(name)) }

var LayerNames = map[config.Layer]string{
	config.LayerHome:     "Дом",
	config.LayerISP:      "Провайдер",
	config.LayerRunet:    "Рунет",
	config.LayerBorder:   "Граница",
	config.LayerForeign:  "Зарубеж",
	config.LayerServices: "Сервисы",
}

func kindTitle(k string) string {
	switch probe.Kind(k) {
	case probe.KindOK:
		return "работает"
	case probe.KindSlow:
		return "отвечает медленно"
	case probe.KindDNSTamper:
		return "подмена DNS"
	case probe.KindDNSFail:
		return "не отвечает DNS"
	case probe.KindIPBlock:
		return "нет соединения по IP"
	case probe.KindSNIBlock:
		return "блокировка по SNI"
	case probe.KindTLSFail:
		return "не устанавливается TLS"
	case probe.KindBlockPage:
		return "страница блокировки"
	case probe.KindGeo:
		return "сервис закрыт для региона"
	case probe.KindCutoff:
		return "обрыв после 16 КБ"
	case probe.KindStall:
		return "загрузка встаёт"
	case probe.KindHTTPError:
		return "ошибка сервера"
	case probe.KindUnreachable:
		return "недоступен"
	}
	return k
}

// KindTitle is the short Russian name of a problem kind.
func KindTitle(k string) string { return kindTitle(k) }

func (m *Monitor) view(c *Check) CheckView {
	v := CheckView{ID: c.ID, Name: c.Name, Group: c.Group, Target: c.Target, Layer: c.Layer, Type: c.Type}
	if r := m.results[c.ID]; r != nil {
		v.Status, v.Kind, v.Summary, v.Value, v.Loss, v.At, v.Since = r.Status, r.Kind, r.Summary, r.Value, r.Loss, r.At, r.Since
		if r.Site != nil {
			v.Steps = r.Site.Steps
		}
	} else {
		v.Summary = "Ещё не проверялся"
	}
	switch c.ID {
	case "gateway":
		if m.gateway != nil {
			v.Target = m.gateway.String()
		}
	case "isp-hop":
		if m.ispHop != nil {
			v.Target = m.ispHop.String()
		}
	}
	return v
}

// compute builds the state from the latest results. Callers hold m.mu; the
// write lock is required when commit is true.
func (m *Monitor) compute(now time.Time) State {
	st := State{At: now, Started: m.started, DownSince: m.downSince, Pi: readPi()}
	if m.gateway != nil {
		st.Gateway = m.gateway.String()
	}
	if m.ispHop != nil {
		st.ISPHop = m.ispHop.String()
	}
	st.PublicIP, st.RuIP, st.City, st.IPSince = m.pub.IP, m.ruIP, m.pub.City, m.ipSince
	st.ISP, st.ASN = ispName(m.pub.Org), asn(m.pub.Org)

	by := map[config.Layer][]CheckView{}
	for _, c := range m.checks {
		v := m.view(c)
		if c.Layer == config.LayerServices {
			st.Services = append(st.Services, v)
			continue
		}
		by[c.Layer] = append(by[c.Layer], v)
	}
	external := false
	for _, l := range []config.Layer{config.LayerRunet, config.LayerForeign} {
		for _, v := range by[l] {
			if v.Status == store.OK || v.Status == store.Warn {
				external = true
			}
		}
	}

	home := evalHome(by[config.LayerHome])
	isp := evalISP(by[config.LayerISP], external)
	runet := evalSegment(config.LayerRunet, by[config.LayerRunet])
	foreign := evalSegment(config.LayerForeign, by[config.LayerForeign])
	border := evalBorder(by[config.LayerBorder], foreign.Status)
	services := evalServices(st.Services)
	st.Layers = []LayerView{home, isp, runet, border, foreign, services}

	for i := range st.Layers {
		l := &st.Layers[i]
		l.Name = LayerNames[l.Layer]
		prev, ok := m.layerStatus[l.Layer]
		if !ok || prev != l.Status {
			m.layerStatus[l.Layer] = l.Status
			m.layerSince[l.Layer] = now
		}
		l.Since = m.layerSince[l.Layer]
	}

	gw := m.results["gateway"]
	st.Warming = now.Sub(m.started) < 10*time.Second || gw == nil
	m.verdict(&st, by)
	return st
}

func worst(vs []CheckView) store.Status {
	w := store.Unknown
	for _, v := range vs {
		if v.Status > w {
			w = v.Status
		}
	}
	return w
}

func evalHome(vs []CheckView) LayerView {
	l := LayerView{Layer: config.LayerHome, Checks: vs}
	if len(vs) == 0 {
		return l
	}
	g := vs[0]
	l.Status = g.Status
	switch g.Status {
	case store.OK:
		l.Summary = fmt.Sprintf("роутер %s", fmtMs(g.Value))
	case store.Warn:
		l.Summary = "роутер с потерями"
	case store.Fail:
		l.Summary = "роутер не отвечает"
	default:
		l.Summary = "нет данных"
	}
	l.Detail = g.Summary
	return l
}

func evalISP(vs []CheckView, external bool) LayerView {
	l := LayerView{Layer: config.LayerISP, Checks: vs}
	var hop, dns CheckView
	for _, v := range vs {
		switch v.ID {
		case "isp-hop":
			hop = v
		case "dns-system":
			dns = v
		}
	}
	hopSt := hop.Status
	if hopSt >= store.Warn && external {
		// Many edge routers ignore ping under load; traffic still flows.
		hopSt = store.OK
	}
	l.Status = max(hopSt, dns.Status)
	if hop.Status == store.Unknown && dns.Status == store.Unknown {
		l.Status = store.Unknown
	}
	switch {
	case l.Status == store.Unknown:
		l.Summary = "нет данных"
	case hop.Status == store.Fail && !external:
		l.Summary = "узел не отвечает"
	case dns.Status == store.Fail:
		l.Summary = "DNS не отвечает"
	case hop.Status == store.OK:
		l.Summary = fmt.Sprintf("узел %s", fmtMs(hop.Value))
	case dns.Status == store.OK:
		l.Summary = fmt.Sprintf("DNS %s", fmtMs(dns.Value))
	default:
		l.Summary = "с перебоями"
	}
	l.Detail = hop.Summary
	if dns.Status >= store.Warn {
		l.Detail = dns.Summary
	}
	return l
}

func evalSegment(layer config.Layer, vs []CheckView) LayerView {
	l := LayerView{Layer: layer, Checks: vs}
	// Some networks drop ICMP while web traffic flows. When every ping fails
	// but sites open, judge the segment by the sites alone.
	var pingOK, pingSeen, siteOK int
	for _, v := range vs {
		if v.Type == TypePing && v.Status != store.Unknown {
			pingSeen++
			if v.Status != store.Fail {
				pingOK++
			}
		}
		if v.Type == TypeSite && v.Status == store.OK {
			siteOK++
		}
	}
	skipPing := pingSeen > 0 && pingOK == 0 && siteOK > 0
	var n, good, soso, bad int
	var pings []float64
	var failed []string
	for _, v := range vs {
		if skipPing && v.Type == TypePing {
			continue
		}
		switch v.Status {
		case store.OK:
			good++
		case store.Warn:
			soso++
		case store.Fail:
			bad++
			failed = append(failed, v.Name)
		default:
			continue
		}
		n++
		if v.Type == TypePing && v.Status != store.Fail && v.Value > 0 {
			pings = append(pings, v.Value)
		}
	}
	l.Failed = bad
	switch {
	case n == 0:
		l.Status = store.Unknown
		l.Summary = "нет данных"
		return l
	case good+soso == 0 || bad*4 >= n*3:
		l.Status = store.Fail
	case bad > 0 || soso > 0:
		l.Status = store.Warn
	default:
		l.Status = store.OK
	}
	switch l.Status {
	case store.OK:
		if len(pings) > 0 {
			sort.Float64s(pings)
			l.Summary = fmtMs(pings[len(pings)/2])
		} else {
			l.Summary = "работает"
		}
		l.Detail = fmt.Sprintf("Отвечают все %d адресов", n)
		if skipPing {
			l.Detail = "Сайты открываются, но ping до узлов не проходит: ICMP где-то фильтруется"
		}
	case store.Fail:
		l.Summary = "не отвечает"
		l.Detail = fmt.Sprintf("Не отвечают %d из %d адресов", bad, n)
	default:
		if bad > 0 {
			l.Summary = fmt.Sprintf("%d из %d не отвечают", bad, n)
			l.Detail = "Не открываются: " + joinRu(failed)
		} else {
			l.Summary = "с перебоями"
			l.Detail = "Есть потери или медленные ответы"
		}
	}
	return l
}

func evalBorder(vs []CheckView, foreign store.Status) LayerView {
	l := LayerView{Layer: config.LayerBorder, Checks: vs}
	if foreign == store.Fail {
		l.Status = store.Unknown
		l.Summary = "не проверить"
		l.Detail = "Без зарубежного интернета ограничения на границе не проверить"
		return l
	}
	var cut, stall, other []string
	var otherText string
	seen := 0
	for _, v := range vs {
		if v.Status == store.Unknown {
			continue
		}
		seen++
		switch {
		case v.Kind == string(probe.KindCutoff):
			cut = append(cut, v.Name)
		case v.Type == TypeThrottle && v.Status >= store.Warn:
			stall = append(stall, v.Name)
		case v.Status >= store.Warn:
			other = append(other, v.Name)
			if otherText == "" {
				otherText = v.Summary
			}
		}
	}
	switch {
	case seen == 0:
		l.Status = store.Unknown
		l.Summary = "нет данных"
	case len(cut) > 0:
		l.Status = store.Warn
		l.Summary = "обрыв на 16 КБ"
		l.Detail = "Соединения обрываются после ~16 КБ: " + joinRu(cut)
	case len(stall) > 0:
		l.Status = store.Warn
		l.Summary = "загрузка встаёт"
		l.Detail = "Файлы с зарубежных хостингов не догружаются: " + joinRu(stall)
	case len(other) > 0:
		l.Status = store.Warn
		l.Summary = "есть ограничения"
		l.Detail = otherText
	default:
		l.Status = store.OK
		l.Summary = "ограничений нет"
		l.Detail = "Файлы с зарубежных хостингов загружаются, DNS не подменяется"
	}
	return l
}

func evalServices(vs []CheckView) LayerView {
	l := LayerView{Layer: config.LayerServices}
	var n, bad int
	for _, v := range vs {
		if v.Status == store.Unknown {
			continue
		}
		n++
		if v.Status >= store.Warn {
			bad++
		}
	}
	switch {
	case n == 0:
		l.Status = store.Unknown
		l.Summary = "нет данных"
	case bad == 0:
		l.Status = store.OK
		l.Summary = fmt.Sprintf("все %d работают", n)
	default:
		l.Status = store.Warn
		l.Summary = fmt.Sprintf("%d из %d с проблемами", bad, n)
	}
	return l
}

func (m *Monitor) verdict(st *State, by map[config.Layer][]CheckView) {
	home, isp := st.layer(config.LayerHome), st.layer(config.LayerISP)
	runet, foreign := st.layer(config.LayerRunet), st.layer(config.LayerForeign)
	border := st.layer(config.LayerBorder)
	set := func(root config.Layer, sev store.Status, since time.Time, head, detail string) {
		st.Root, st.Severity, st.Since, st.Headline, st.Detail = root, sev, since, head, detail
	}
	var dns CheckView
	for _, v := range by[config.LayerISP] {
		if v.ID == "dns-system" {
			dns = v
		}
	}
	var blocked []string
	var fresh []CheckView
	for _, s := range st.Services {
		if s.Status == store.Fail {
			blocked = append(blocked, s.Name)
			if st.At.Sub(s.Since) < 24*time.Hour && s.Since.After(m.started.Add(5*time.Minute)) {
				fresh = append(fresh, s)
			}
		}
	}

	switch {
	case st.Warming:
		set("", store.Unknown, st.At, "Собираю первые данные", "Результаты появятся через несколько секунд.")
	case st.Gateway == "" && !anyExternal(by):
		set(config.LayerHome, store.Fail, home.Since, "Нет маршрута в интернет",
			"Pi не знает адрес роутера: нет маршрута по умолчанию. Проверь кабель до Pi и раздачу адресов (DHCP) на роутере.")
	case home.Status == store.Fail && !st.Pi.HasNetwork:
		set(config.LayerHome, store.Fail, home.Since, "Raspberry Pi потеряла сеть",
			"У Pi нет активного сетевого подключения. Проверь кабель до Pi.")
	case home.Status == store.Fail:
		set(config.LayerHome, store.Fail, home.Since, "Нет связи с роутером",
			fmt.Sprintf("Роутер %s не отвечает. Проверь питание роутера и кабель до Pi.", orDash(st.Gateway)))
	case dns.Status == store.Fail && (isp.Status != store.Fail || anyPing(by)):
		set(config.LayerISP, store.Fail, dns.Since, "Не работает DNS",
			"Адреса доступны напрямую, но имена сайтов не превращаются в адреса. Проверь DNS в настройках роутера или временно укажи 77.88.8.8.")
	case isp.Status == store.Fail || (runet.Status == store.Fail && foreign.Status == store.Fail):
		detail := "Сеть провайдера отвечает, но дальше пакеты не проходят: не открываются ни российские, ни зарубежные адреса."
		if isp.Status == store.Fail {
			detail = fmt.Sprintf("Первый узел провайдера %s не отвечает. Авария у провайдера или роутер потерял подключение.", orDash(st.ISPHop))
		}
		set(config.LayerISP, store.Fail, earliest(isp, runet, foreign), "Роутер на связи, интернета нет", detail)
	case foreign.Status == store.Fail:
		set(config.LayerForeign, store.Fail, foreign.Since, "Работает только российский интернет",
			"Зарубежные адреса не отвечают, российские открываются. Так выглядит отключение внешних каналов или режим белых списков.")
	case runet.Status == store.Fail:
		set(config.LayerRunet, store.Fail, runet.Since, "Российские сайты не открываются",
			"Зарубежные при этом работают. Похоже на сбой внутри российского сегмента или у провайдера.")
	case border.Status == store.Warn && border.Summary == "обрыв на 16 КБ":
		set(config.LayerBorder, store.Warn, border.Since, "Зарубежные хостинги обрывают соединения после 16 КБ",
			border.Detail+". Сайты на этих хостингах грузятся частично или не грузятся. Российский интернет работает.")
	case foreign.Status == store.Warn && foreign.Failed > 0:
		set(config.LayerForeign, store.Warn, foreign.Since, "Часть зарубежных сайтов не открывается", foreign.Detail+".")
	case runet.Status == store.Warn && runet.Failed > 0:
		set(config.LayerRunet, store.Warn, runet.Since, "Часть российских сайтов не открывается", runet.Detail+".")
	case foreign.Status == store.Warn:
		set(config.LayerForeign, store.Warn, foreign.Since, "Зарубежные сайты отвечают с задержками", slowList(by[config.LayerForeign]))
	case runet.Status == store.Warn:
		set(config.LayerRunet, store.Warn, runet.Since, "Российские сайты отвечают с задержками", slowList(by[config.LayerRunet]))
	case home.Status == store.Warn:
		set(config.LayerHome, store.Warn, home.Since, "Связь с роутером нестабильна", home.Detail+". Проблема внутри дома: кабель, порт или сам роутер.")
	case isp.Status == store.Warn:
		set(config.LayerISP, store.Warn, isp.Since, "Интернет есть, но с потерями у провайдера", isp.Detail+".")
	case border.Status == store.Warn:
		set(config.LayerBorder, store.Warn, border.Since, "На выходе за границу есть ограничения", border.Detail+".")
	case len(fresh) == 1:
		s := fresh[0]
		set(config.LayerServices, store.Warn, s.Since, "Перестал открываться "+s.Name, upper(kindTitle(s.Kind))+". "+s.Summary+".")
	case len(fresh) > 1:
		var names []string
		for _, s := range fresh {
			names = append(names, s.Name)
		}
		set(config.LayerServices, store.Warn, fresh[0].Since, "Перестали открываться: "+joinRu(names),
			"Остальной интернет работает. Подробности на вкладке «Сервисы».")
	default:
		detail := "Российские и зарубежные сайты открываются."
		if strings.HasSuffix(runet.Summary, "мс") && strings.HasSuffix(foreign.Summary, "мс") {
			detail = fmt.Sprintf("Задержка до российских узлов %s, до зарубежных %s.", runet.Summary, foreign.Summary)
		}
		if len(blocked) > 0 {
			detail += " Не открываются: " + joinRu(blocked) + "."
		}
		set("", store.OK, earliest(home, isp, runet, foreign), "Интернет работает", detail)
	}
}

func slowList(vs []CheckView) string {
	var out []string
	for _, v := range vs {
		if v.Status == store.Warn {
			out = append(out, v.Name+": "+lowerFirst(v.Summary))
		}
	}
	if len(out) == 0 {
		return "Есть потери или медленные ответы."
	}
	return strings.Join(out, "; ") + "."
}

func lowerFirst(s string) string {
	r := []rune(s)
	if len(r) > 1 && r[0] >= 'А' && r[0] <= 'Я' && !(r[1] >= 'А' && r[1] <= 'Я') {
		r[0] += 'а' - 'А'
	}
	return string(r)
}

func anyExternal(by map[config.Layer][]CheckView) bool {
	for _, l := range []config.Layer{config.LayerRunet, config.LayerForeign} {
		for _, v := range by[l] {
			if v.Status == store.OK || v.Status == store.Warn {
				return true
			}
		}
	}
	return false
}

func anyPing(by map[config.Layer][]CheckView) bool {
	for _, l := range []config.Layer{config.LayerRunet, config.LayerForeign} {
		for _, v := range by[l] {
			if v.Type == TypePing && v.Status == store.OK {
				return true
			}
		}
	}
	return false
}

// earliest picks the latest of the change times: the state as a whole has
// held only since its most recent component changed.
func earliest(ls ...LayerView) time.Time {
	var t time.Time
	for _, l := range ls {
		if l.Since.After(t) {
			t = l.Since
		}
	}
	return t
}

func fmtMs(v float64) string {
	switch {
	case v <= 0:
		return "—"
	case v < 10:
		return fmt.Sprintf("%.1f мс", v)
	}
	return fmt.Sprintf("%.0f мс", v)
}

// FmtMs formats milliseconds for display.
func FmtMs(v float64) string { return fmtMs(v) }

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

func upper(s string) string {
	r := []rune(s)
	if len(r) == 0 {
		return s
	}
	if r[0] >= 'а' && r[0] <= 'я' {
		r[0] -= 'а' - 'А'
	}
	return string(r)
}
