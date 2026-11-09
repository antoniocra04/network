package web

import (
	"fmt"
	"html/template"
	"math"
	"strings"
	"time"

	"github.com/antoniocra04/svyaz/internal/store"
)

// timelineRow draws one layer's 24 h history as runs of equal status.
// Gaps without snapshots are drawn as "no data", never as an outage.
func timelineRow(snaps []store.Snapshot, layer string, from, to time.Time, bucket time.Duration) template.HTML {
	n := int(to.Sub(from) / bucket)
	cells := make([]store.Status, n)
	have := make([]bool, n)
	for _, s := range snaps {
		i := int(s.TS.Sub(from) / bucket)
		if i < 0 || i >= n {
			continue
		}
		v := s.Layers[layer]
		if v > cells[i] {
			cells[i] = v
		}
		have[i] = true
	}
	var b strings.Builder
	fmt.Fprintf(&b, `<svg class="tl-row" viewBox="0 0 %d 1" preserveAspectRatio="none" role="img" aria-label="История за 24 часа">`, n)
	for i := 0; i < n; {
		j := i
		for j < n && cells[j] == cells[i] && have[j] == have[i] {
			j++
		}
		cls := "none"
		word := "нет данных"
		if have[i] {
			cls = statusClass(cells[i])
			word = strings.ToLower(statusWord(cells[i]))
		}
		start := from.Add(time.Duration(i) * bucket).Local()
		end := from.Add(time.Duration(j) * bucket).Local()
		fmt.Fprintf(&b, `<rect class="c-%s" x="%d" y="0" width="%d" height="1"><title>%s–%s · %s</title></rect>`,
			cls, i, j-i, start.Format("15:04"), end.Format("15:04"), word)
		i = j
	}
	b.WriteString(`</svg>`)
	return template.HTML(b.String())
}

// Series colours, categorical slots 1–3 for a dark surface.
var seriesColors = []string{"#3987e5", "#d95926", "#199e70"}

type chartSeries struct {
	Name   string
	Color  string
	Points []store.Point
}

// latencyChart plots latency on one fixed logarithmic scale (1 ms – 1 s)
// shared by every chart, so values are comparable across panels. The plot
// stretches to any width; axis labels are HTML so they stay readable.
func latencyChart(series []chartSeries, from, to time.Time, bucket time.Duration) template.HTML {
	const W, H = 1000.0, 160.0
	span := to.Sub(from)
	xf := func(t time.Time) float64 { return float64(t.Sub(from)) / float64(span) }
	yf := func(v float64) float64 {
		v = math.Max(1, math.Min(1000, v))
		return 1 - math.Log10(v)/3
	}
	var b strings.Builder
	b.WriteString(`<div class="chart" role="img" aria-label="Задержка в миллисекундах, логарифмическая шкала"><div class="plot">`)
	for _, g := range []struct {
		v     float64
		label string
	}{{1, "1 мс"}, {10, "10 мс"}, {100, "100 мс"}, {1000, "1 с"}} {
		fmt.Fprintf(&b, `<span class="ylab" style="top:%.2f%%">%s</span>`, yf(g.v)*100, g.label)
	}
	fmt.Fprintf(&b, `<svg viewBox="0 0 %.0f %.0f" preserveAspectRatio="none">`, W, H)
	for _, v := range []float64{1, 10, 100, 1000} {
		fmt.Fprintf(&b, `<line class="grid" x1="0" x2="%.0f" y1="%.1f" y2="%.1f"/>`, W, yf(v)*H, yf(v)*H)
	}
	for _, s := range series {
		// Break the line where a bucket has no successful replies.
		var path strings.Builder
		pen := false
		for _, p := range s.Points {
			if p.Value <= 0 || p.OK == 0 {
				pen = false
				continue
			}
			cmd := "L"
			if !pen {
				cmd = "M"
			}
			fmt.Fprintf(&path, "%s%.1f %.1f", cmd, xf(p.TS.Add(bucket/2))*W, yf(p.Value)*H)
			pen = true
		}
		fmt.Fprintf(&b, `<path class="line" stroke="%s" d="%s"/>`, s.Color, path.String())
		// Lost packets: a tick rising from the baseline, taller for more loss.
		bw := math.Max(W*float64(bucket)/float64(span)*0.6, 2)
		for _, p := range s.Points {
			if p.Total > 0 && p.OK < p.Total {
				loss := 1 - float64(p.OK)/float64(p.Total)
				h := math.Max(6, loss*30)
				fmt.Fprintf(&b, `<rect class="loss" x="%.1f" y="%.1f" width="%.1f" height="%.1f" fill="%s"/>`,
					xf(p.TS)*W, H-h, bw, h, s.Color)
			}
		}
	}
	// Hover targets: one column per bucket listing every series.
	byTS := map[int64][]string{}
	var order []int64
	for _, s := range series {
		for _, p := range s.Points {
			k := p.TS.Unix()
			if _, ok := byTS[k]; !ok {
				order = append(order, k)
			}
			v := "нет ответа"
			if p.OK > 0 {
				v = ms(p.Value)
			}
			if p.Total > 0 && p.OK < p.Total {
				v += fmt.Sprintf(", потери %.0f%%", (1-float64(p.OK)/float64(p.Total))*100)
			}
			byTS[k] = append(byTS[k], s.Name+": "+v)
		}
	}
	bw := math.Max(W*float64(bucket)/float64(span), 2)
	for _, k := range order {
		t := time.Unix(k, 0)
		fmt.Fprintf(&b, `<rect class="hit" x="%.1f" y="0" width="%.1f" height="%.0f"><title>%s
%s</title></rect>`, xf(t)*W, bw, H, t.Local().Format("15:04"), strings.Join(byTS[k], "\n"))
	}
	b.WriteString(`</svg></div>`)
	step := 4 * time.Hour
	if span <= 6*time.Hour {
		step = time.Hour
	} else if span > 48*time.Hour {
		step = 24 * time.Hour
	}
	b.WriteString(`<div class="xlabs">`)
	for t := from.Truncate(step).Add(step); t.Before(to); t = t.Add(step) {
		label := t.Local().Format("15:04")
		if step == 24*time.Hour {
			label = dateShort(t)
		}
		fmt.Fprintf(&b, `<span style="left:%.2f%%">%s</span>`, xf(t)*100, label)
	}
	b.WriteString(`</div>`)
	b.WriteString(`</div>`)
	return template.HTML(b.String())
}

type calDay struct {
	Day   time.Time
	Class string
	Title string
}

// calendarDays turns daily stats into 13 weeks of cells, Monday first.
func calendarDays(stats []store.DayStat, now time.Time) []calDay {
	byDay := map[string]store.DayStat{}
	for _, s := range stats {
		byDay[s.Day.Format("2006-01-02")] = s
	}
	now = now.Local()
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.Local)
	wd := (int(today.Weekday()) + 6) % 7
	start := today.AddDate(0, 0, -wd-12*7)
	var out []calDay
	for d := start; !d.After(today.AddDate(0, 0, 6-wd)); d = d.AddDate(0, 0, 1) {
		c := calDay{Day: d}
		s, ok := byDay[d.Format("2006-01-02")]
		switch {
		case d.After(today):
			c.Class = "future"
		case !ok || s.Samples == 0:
			c.Class = "none"
			c.Title = dateShort(d) + " · нет данных"
		default:
			bad := float64(s.Bad) / float64(s.Samples)
			worse := float64(s.Worse) / float64(s.Samples)
			up := 1 - bad
			switch {
			case bad > 0.02:
				c.Class = "fail"
			case bad > 0 || worse > 0.05:
				c.Class = "warn"
			default:
				c.Class = "ok"
			}
			c.Title = fmt.Sprintf("%s · интернет был %.1f%% времени, с перебоями %.1f%%", dateShort(d), up*100, worse*100)
		}
		out = append(out, c)
	}
	return out
}
