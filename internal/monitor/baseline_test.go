package monitor

import (
	"testing"
	"time"

	"github.com/antoniocra04/network/internal/store"
)

func newTestMonitor(t *testing.T) *Monitor {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return &Monitor{store: st, base: map[string]*baseline{}}
}

func feed(m *Monitor, id string, s store.Status, at time.Time) {
	m.observe(id, &Result{Status: s, At: at})
}

func TestUsualBlockIsQuiet(t *testing.T) {
	m := newTestMonitor(t)
	t0 := time.Now()
	// A service blocked from the start becomes "usual" after two results.
	feed(m, "telegram", store.Fail, t0)
	if ch, usual, _ := m.change("telegram", store.Fail); ch != ChangeNone || usual {
		t.Fatalf("one result must not teach the usual state: %q %v", ch, usual)
	}
	feed(m, "telegram", store.Fail, t0.Add(time.Minute))
	if ch, usual, _ := m.change("telegram", store.Fail); ch != ChangeNone || !usual {
		t.Fatalf("known block should be usual and quiet, got %q usual=%v", ch, usual)
	}
	// It opening again is news.
	feed(m, "telegram", store.OK, t0.Add(2*time.Minute))
	if ch, _, since := m.change("telegram", store.OK); ch != ChangeFixed || !since.Equal(t0.Add(2*time.Minute)) {
		t.Fatalf("want fixed since the first good result, got %q %v", ch, since)
	}
}

func TestNewBlockIsNewsUntilItBecomesNormal(t *testing.T) {
	m := newTestMonitor(t)
	t0 := time.Now()
	feed(m, "whatsapp", store.OK, t0)
	feed(m, "whatsapp", store.OK, t0.Add(time.Minute))
	feed(m, "whatsapp", store.Fail, t0.Add(2*time.Minute))
	if ch, _, _ := m.change("whatsapp", store.Fail); ch != ChangeBroke {
		t.Fatalf("a working service that stops is news, got %q", ch)
	}
	// A slowdown counts as not working too.
	feed(m, "whatsapp", store.Warn, t0.Add(3*time.Minute))
	if ch, _, since := m.change("whatsapp", store.Warn); ch != ChangeBroke || !since.Equal(t0.Add(2*time.Minute)) {
		t.Fatalf("departure should keep its start time, got %q %v", ch, since)
	}
	// After a day it is the new normal.
	feed(m, "whatsapp", store.Fail, t0.Add(2*time.Minute+newNormalAfter))
	if ch, usual, _ := m.change("whatsapp", store.Fail); ch != ChangeNone || !usual {
		t.Fatalf("a day-long block should become usual, got %q usual=%v", ch, usual)
	}
}

func TestUsualStateSurvivesRestart(t *testing.T) {
	m := newTestMonitor(t)
	t0 := time.Now()
	feed(m, "chatgpt", store.Fail, t0)
	feed(m, "chatgpt", store.Fail, t0.Add(time.Minute))
	restarted := &Monitor{store: m.store, base: map[string]*baseline{}}
	feed(restarted, "chatgpt", store.Fail, t0.Add(2*time.Minute))
	if _, usual, _ := restarted.change("chatgpt", store.Fail); !usual {
		t.Fatal("usual state should be read back from the database")
	}
}
