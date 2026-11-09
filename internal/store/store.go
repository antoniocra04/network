// Package store keeps measurement history in SQLite.
package store

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

// Status of a check or a layer. Order matters: higher is worse, except
// Unknown which means "no data".
type Status int

const (
	Unknown Status = 0
	OK      Status = 1
	Warn    Status = 2
	Fail    Status = 3
)

type Store struct{ db *sql.DB }

const schema = `
CREATE TABLE IF NOT EXISTS samples(
	ts INTEGER NOT NULL, check_id TEXT NOT NULL, status INTEGER NOT NULL,
	value REAL, kind TEXT);
CREATE INDEX IF NOT EXISTS samples_check_ts ON samples(check_id, ts);
CREATE TABLE IF NOT EXISTS snapshots(
	ts INTEGER PRIMARY KEY, home INTEGER, isp INTEGER, runet INTEGER,
	border INTEGER, foreign_ INTEGER, services INTEGER, headline TEXT);
CREATE TABLE IF NOT EXISTS incidents(
	id INTEGER PRIMARY KEY AUTOINCREMENT, layer TEXT NOT NULL, subject TEXT NOT NULL,
	severity INTEGER NOT NULL, title TEXT NOT NULL, detail TEXT,
	started INTEGER NOT NULL, ended INTEGER, snapshot TEXT);
CREATE INDEX IF NOT EXISTS incidents_started ON incidents(started);
CREATE TABLE IF NOT EXISTS boots(ts INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS kv(k TEXT PRIMARY KEY, v TEXT);
`

func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	dsn := "file:" + filepath.Join(dir, "svyaz.db") + "?_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=busy_timeout(5000)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schema); err != nil {
		return nil, fmt.Errorf("schema: %w", err)
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

type Sample struct {
	TS      time.Time
	CheckID string
	Status  Status
	Value   float64
	Kind    string
}

func (s *Store) AddSamples(ss []Sample) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	st, err := tx.Prepare(`INSERT INTO samples(ts, check_id, status, value, kind) VALUES(?,?,?,?,?)`)
	if err != nil {
		tx.Rollback()
		return err
	}
	for _, x := range ss {
		if _, err := st.Exec(x.TS.Unix(), x.CheckID, int(x.Status), x.Value, x.Kind); err != nil {
			tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

// Snapshot is the state of every layer at one moment.
type Snapshot struct {
	TS       time.Time
	Layers   map[string]Status
	Headline string
}

var layerCols = []string{"home", "isp", "runet", "border", "foreign_", "services"}

func col(layer string) string {
	if layer == "foreign" {
		return "foreign_"
	}
	return layer
}

func (s *Store) AddSnapshot(sn Snapshot) error {
	_, err := s.db.Exec(`INSERT OR REPLACE INTO snapshots(ts, home, isp, runet, border, foreign_, services, headline)
		VALUES(?,?,?,?,?,?,?,?)`, sn.TS.Unix(),
		sn.Layers["home"], sn.Layers["isp"], sn.Layers["runet"], sn.Layers["border"],
		sn.Layers["foreign"], sn.Layers["services"], sn.Headline)
	return err
}

// Snapshots returns snapshots in [from, to) ordered by time.
func (s *Store) Snapshots(from, to time.Time) ([]Snapshot, error) {
	rows, err := s.db.Query(`SELECT ts, home, isp, runet, border, foreign_, services, headline
		FROM snapshots WHERE ts >= ? AND ts < ? ORDER BY ts`, from.Unix(), to.Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Snapshot
	for rows.Next() {
		var ts int64
		var v [6]int
		var h sql.NullString
		if err := rows.Scan(&ts, &v[0], &v[1], &v[2], &v[3], &v[4], &v[5], &h); err != nil {
			return nil, err
		}
		sn := Snapshot{TS: time.Unix(ts, 0), Headline: h.String, Layers: map[string]Status{}}
		for i, c := range layerCols {
			name := c
			if c == "foreign_" {
				name = "foreign"
			}
			sn.Layers[name] = Status(v[i])
		}
		out = append(out, sn)
	}
	return out, rows.Err()
}

// DayStat is the share of time each status held during one day.
type DayStat struct {
	Day     time.Time
	Samples int
	Bad     int // samples where the internet as a whole was down
	Worse   int // samples with any degraded layer
}

// Days aggregates snapshots per local day for the overall connection.
func (s *Store) Days(from time.Time, loc *time.Location) ([]DayStat, error) {
	rows, err := s.db.Query(`SELECT ts, home, isp, runet, foreign_, border FROM snapshots WHERE ts >= ? ORDER BY ts`, from.Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	byDay := map[string]*DayStat{}
	var order []string
	for rows.Next() {
		var ts int64
		var home, isp, runet, foreign, border int
		if err := rows.Scan(&ts, &home, &isp, &runet, &foreign, &border); err != nil {
			return nil, err
		}
		t := time.Unix(ts, 0).In(loc)
		key := t.Format("2006-01-02")
		d, ok := byDay[key]
		if !ok {
			y, m, dd := t.Date()
			d = &DayStat{Day: time.Date(y, m, dd, 0, 0, 0, 0, loc)}
			byDay[key] = d
			order = append(order, key)
		}
		d.Samples++
		if home == int(Fail) || isp == int(Fail) || (runet == int(Fail) && foreign == int(Fail)) {
			d.Bad++
		} else if runet >= int(Warn) || foreign >= int(Warn) || border >= int(Warn) || home >= int(Warn) || isp >= int(Warn) {
			d.Worse++
		}
	}
	out := make([]DayStat, 0, len(order))
	for _, k := range order {
		out = append(out, *byDay[k])
	}
	return out, rows.Err()
}

// Point is one bucket of a time series.
type Point struct {
	TS    time.Time
	Value float64 // average of non-failed samples, NaN-free; 0 when none
	OK    int
	Total int
}

// Series buckets a check's samples into fixed intervals.
func (s *Store) Series(checkID string, from time.Time, bucket time.Duration) ([]Point, error) {
	b := int64(bucket.Seconds())
	rows, err := s.db.Query(`SELECT (ts / ?) * ?, AVG(CASE WHEN status != 3 THEN value END),
			SUM(CASE WHEN status = 1 THEN 1 ELSE 0 END), COUNT(*)
		FROM samples WHERE check_id = ? AND ts >= ? GROUP BY ts / ? ORDER BY 1`,
		b, b, checkID, from.Unix(), b)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Point
	for rows.Next() {
		var ts int64
		var v sql.NullFloat64
		var p Point
		if err := rows.Scan(&ts, &v, &p.OK, &p.Total); err != nil {
			return nil, err
		}
		p.TS = time.Unix(ts, 0)
		p.Value = v.Float64
		out = append(out, p)
	}
	return out, rows.Err()
}

type Incident struct {
	ID       int64
	Layer    string
	Subject  string
	Severity Status
	Title    string
	Detail   string
	Started  time.Time
	Ended    time.Time // zero while open
	Snapshot string
}

func (i Incident) Open() bool { return i.Ended.IsZero() }

func (i Incident) Duration(now time.Time) time.Duration {
	if i.Open() {
		return now.Sub(i.Started)
	}
	return i.Ended.Sub(i.Started)
}

func (s *Store) OpenIncident(in Incident) (int64, error) {
	r, err := s.db.Exec(`INSERT INTO incidents(layer, subject, severity, title, detail, started, snapshot) VALUES(?,?,?,?,?,?,?)`,
		in.Layer, in.Subject, int(in.Severity), in.Title, in.Detail, in.Started.Unix(), in.Snapshot)
	if err != nil {
		return 0, err
	}
	return r.LastInsertId()
}

func (s *Store) UpdateIncident(id int64, severity Status, title, detail string) error {
	_, err := s.db.Exec(`UPDATE incidents SET severity = MAX(severity, ?), title = ?, detail = ? WHERE id = ?`, int(severity), title, detail, id)
	return err
}

func (s *Store) CloseIncident(id int64, at time.Time) error {
	_, err := s.db.Exec(`UPDATE incidents SET ended = ? WHERE id = ?`, at.Unix(), id)
	return err
}

// CloseAllOpen closes incidents left open by a previous run at the given time.
func (s *Store) CloseAllOpen(at time.Time) error {
	_, err := s.db.Exec(`UPDATE incidents SET ended = MAX(started, ?) WHERE ended IS NULL`, at.Unix())
	return err
}

func (s *Store) Incidents(from time.Time, limit int) ([]Incident, error) {
	rows, err := s.db.Query(`SELECT id, layer, subject, severity, title, COALESCE(detail,''), started, ended, COALESCE(snapshot,'')
		FROM incidents WHERE started >= ? OR ended IS NULL OR ended >= ? ORDER BY started DESC LIMIT ?`, from.Unix(), from.Unix(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Incident
	for rows.Next() {
		var in Incident
		var started int64
		var ended sql.NullInt64
		var sev int
		if err := rows.Scan(&in.ID, &in.Layer, &in.Subject, &sev, &in.Title, &in.Detail, &started, &ended, &in.Snapshot); err != nil {
			return nil, err
		}
		in.Severity = Status(sev)
		in.Started = time.Unix(started, 0)
		if ended.Valid {
			in.Ended = time.Unix(ended.Int64, 0)
		}
		out = append(out, in)
	}
	return out, rows.Err()
}

func (s *Store) Incident(id int64) (Incident, error) {
	var in Incident
	var started int64
	var ended sql.NullInt64
	var sev int
	err := s.db.QueryRow(`SELECT id, layer, subject, severity, title, COALESCE(detail,''), started, ended, COALESCE(snapshot,'')
		FROM incidents WHERE id = ?`, id).Scan(&in.ID, &in.Layer, &in.Subject, &sev, &in.Title, &in.Detail, &started, &ended, &in.Snapshot)
	in.Severity = Status(sev)
	in.Started = time.Unix(started, 0)
	if ended.Valid {
		in.Ended = time.Unix(ended.Int64, 0)
	}
	return in, err
}

// RecordBoot stores the start time and returns the time of the last snapshot
// before it, so the gap can be shown as "no data".
func (s *Store) RecordBoot(now time.Time) (time.Time, error) {
	var last sql.NullInt64
	if err := s.db.QueryRow(`SELECT MAX(ts) FROM snapshots`).Scan(&last); err != nil {
		return time.Time{}, err
	}
	if _, err := s.db.Exec(`INSERT INTO boots(ts) VALUES(?)`, now.Unix()); err != nil {
		return time.Time{}, err
	}
	if !last.Valid {
		return time.Time{}, nil
	}
	return time.Unix(last.Int64, 0), nil
}

func (s *Store) Boots(from time.Time) ([]time.Time, error) {
	rows, err := s.db.Query(`SELECT ts FROM boots WHERE ts >= ? ORDER BY ts`, from.Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []time.Time
	for rows.Next() {
		var ts int64
		if err := rows.Scan(&ts); err != nil {
			return nil, err
		}
		out = append(out, time.Unix(ts, 0))
	}
	return out, rows.Err()
}

func (s *Store) SetKV(k, v string) error {
	_, err := s.db.Exec(`INSERT INTO kv(k, v) VALUES(?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v`, k, v)
	return err
}

func (s *Store) KV(k string) string {
	var v string
	s.db.QueryRow(`SELECT v FROM kv WHERE k = ?`, k).Scan(&v)
	return v
}

// Prune drops raw samples older than keepSamples and snapshots older than keepSnapshots.
func (s *Store) Prune(now time.Time, keepSamples, keepSnapshots time.Duration) error {
	if _, err := s.db.Exec(`DELETE FROM samples WHERE ts < ?`, now.Add(-keepSamples).Unix()); err != nil {
		return err
	}
	_, err := s.db.Exec(`DELETE FROM snapshots WHERE ts < ?`, now.Add(-keepSnapshots).Unix())
	return err
}
