package monitor

import (
	"time"

	"github.com/antoniocra04/network/internal/store"
)

// A service's usual state is learned rather than configured: whatever it
// settles into is "as usual", and only a departure from it is news. A known
// block (Telegram, ChatGPT) stays quiet; a service that used to open and
// stopped is what the owner needs to see.

// newNormalAfter is how long a departure lasts before it becomes the usual state.
const newNormalAfter = 24 * time.Hour

type baseline struct {
	usual   string // "ok" or "bad"; empty until learned
	seen    string // category of the previous result, for the first learning
	seenN   int
	devCat  string // category of the current departure, if any
	devFrom time.Time
}

// Change describes how a service differs from its usual state.
type Change string

const (
	ChangeNone  Change = ""
	ChangeBroke Change = "broke" // usually opens, now does not
	ChangeFixed Change = "fixed" // usually blocked, now opens
)

func category(s store.Status) string {
	if s == store.OK {
		return "ok"
	}
	return "bad"
}

func baseKey(id string) string { return "svc_usual:" + id }

// observe updates the learned state with a new result. Callers hold m.mu.
func (m *Monitor) observe(id string, r *Result) {
	if r.Status == store.Unknown {
		return
	}
	b := m.base[id]
	if b == nil {
		b = &baseline{usual: m.store.KV(baseKey(id))}
		m.base[id] = b
	}
	cat := category(r.Status)
	switch {
	case b.usual == "":
		// Learn the starting state from two matching results in a row.
		if cat == b.seen {
			b.seenN++
		} else {
			b.seen, b.seenN = cat, 1
		}
		if b.seenN >= 2 {
			b.usual = cat
			m.store.SetKV(baseKey(id), cat)
		}
	case cat == b.usual:
		b.devCat, b.devFrom = "", time.Time{}
	default:
		if b.devCat != cat {
			b.devCat, b.devFrom = cat, r.At
		}
		if r.At.Sub(b.devFrom) >= newNormalAfter {
			b.usual = cat
			b.devCat, b.devFrom = "", time.Time{}
			m.store.SetKV(baseKey(id), cat)
		}
	}
}

// change reports the departure from the usual state and since when.
func (m *Monitor) change(id string, s store.Status) (Change, bool, time.Time) {
	b := m.base[id]
	if b == nil || b.usual == "" || s == store.Unknown {
		return ChangeNone, false, time.Time{}
	}
	cat := category(s)
	switch {
	case cat == b.usual:
		return ChangeNone, cat == "bad", time.Time{}
	case b.usual == "ok":
		return ChangeBroke, false, b.devFrom
	}
	return ChangeFixed, false, b.devFrom
}
