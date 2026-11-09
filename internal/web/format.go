package web

import (
	"fmt"
	"html/template"
	"net/url"
	"time"

	"github.com/antoniocra04/network/internal/monitor"
	"github.com/antoniocra04/network/internal/store"
)

var months = []string{"янв", "фев", "мар", "апр", "мая", "июн", "июл", "авг", "сен", "окт", "ноя", "дек"}

// clock prints a time relative to now: "14:02", "вчера 14:02", "8 ноя 14:02".
func clock(t time.Time) string {
	if t.IsZero() {
		return "—"
	}
	t = t.Local()
	now := time.Now()
	y1, m1, d1 := now.Date()
	y2, m2, d2 := t.Date()
	switch {
	case y1 == y2 && m1 == m2 && d1 == d2:
		return t.Format("15:04")
	case now.Sub(t) < 48*time.Hour && now.AddDate(0, 0, -1).Day() == d2:
		return "вчера " + t.Format("15:04")
	case y1 == y2:
		return fmt.Sprintf("%d %s %s", d2, months[m2-1], t.Format("15:04"))
	}
	return fmt.Sprintf("%d %s %d", d2, months[m2-1], y2)
}

func dateShort(t time.Time) string {
	t = t.Local()
	return fmt.Sprintf("%d %s", t.Day(), months[t.Month()-1])
}

// dur prints a duration in the largest two units: "2 ч 10 мин".
func dur(d time.Duration) string {
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%d с", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%d мин", int(d.Minutes()))
	case d < 24*time.Hour:
		h := int(d.Hours())
		m := int(d.Minutes()) % 60
		if m == 0 {
			return fmt.Sprintf("%d ч", h)
		}
		return fmt.Sprintf("%d ч %d мин", h, m)
	}
	days := int(d.Hours()) / 24
	h := int(d.Hours()) % 24
	if h == 0 {
		return fmt.Sprintf("%d дн", days)
	}
	return fmt.Sprintf("%d дн %d ч", days, h)
}

func since(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return dur(time.Since(t))
}

func statusClass(s store.Status) string {
	switch s {
	case store.OK:
		return "ok"
	case store.Warn:
		return "warn"
	case store.Fail:
		return "fail"
	}
	return "none"
}

func statusWord(s store.Status) string {
	switch s {
	case store.OK:
		return "Работает"
	case store.Warn:
		return "С перебоями"
	case store.Fail:
		return "Не работает"
	}
	return "Нет данных"
}

// icon draws the status shape so state is never carried by color alone:
// a check, a triangle, a cross, a dashed ring.
func icon(s store.Status) template.HTML {
	const open = `<svg class="ic ic-%s" viewBox="0 0 16 16" aria-hidden="true">%s</svg>`
	var body string
	switch s {
	case store.OK:
		body = `<circle cx="8" cy="8" r="7"/><path d="M4.8 8.3l2.1 2.1 4.3-4.6" fill="none"/>`
	case store.Warn:
		body = `<path d="M8 1.6l6.9 12.2H1.1z"/><path d="M8 6v3.6M8 11.4v.2" fill="none"/>`
	case store.Fail:
		body = `<circle cx="8" cy="8" r="7"/><path d="M5.5 5.5l5 5M10.5 5.5l-5 5" fill="none"/>`
	default:
		body = `<circle cx="8" cy="8" r="6.2" fill="none" stroke-dasharray="2.2 2.2"/>`
	}
	return template.HTML(fmt.Sprintf(open, statusClass(s), body))
}

func ms(v float64) string { return monitor.FmtMs(v) }

var funcs = template.FuncMap{
	"clock":       clock,
	"dur":         dur,
	"since":       since,
	"statusClass": statusClass,
	"statusWord":  statusWord,
	"icon":        icon,
	"ms":          ms,
	"kindTitle":   monitor.KindTitle,
	"dateShort":   dateShort,
	"host": func(target string) string {
		if u, err := url.Parse(target); err == nil && u.Host != "" {
			return u.Host
		}
		return target
	},
	"cap": func(s string) string {
		r := []rune(s)
		if len(r) > 0 && r[0] >= 'а' && r[0] <= 'я' {
			r[0] -= 'а' - 'А'
		}
		return string(r)
	},
	"pct": func(v float64) string {
		return fmt.Sprintf("%.0f%%", v*100)
	},
	"temp": func(v float64) string {
		if v == 0 {
			return "—"
		}
		return fmt.Sprintf("%.0f °C", v)
	},
	"gb":   func(v float64) string { return fmt.Sprintf("%.1f ГБ", v) },
	"isOK": func(s store.Status) bool { return s == store.OK },
	"bad":  func(s store.Status) bool { return s >= store.Warn },
	"durBetween": func(a, b time.Time) string {
		if b.IsZero() {
			b = time.Now()
		}
		return dur(b.Sub(a))
	},
	"incDur": func(i store.Incident) string { return dur(i.Duration(time.Now())) },
	"layerName": func(l string) string {
		if l == "services" {
			return "Сервис"
		}
		for k, v := range monitor.LayerNames {
			if string(k) == l {
				return v
			}
		}
		return l
	},
}
