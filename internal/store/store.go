package store

import (
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	// Pure-Go SQLite (no cgo): keeps binaries static.
	_ "modernc.org/sqlite"
)

// Client is one registered device identity.
type Client struct {
	ID        int64     `json:"id"`
	Name      string    `json:"name"`
	Token     string    `json:"token"`
	CreatedAt time.Time `json:"created_at"`
	LastSeen  time.Time `json:"last_seen"`
	Active    bool      `json:"active"`
}

// ErrNotFound is returned when a row does not exist.
var ErrNotFound = errors.New("not found")

// Store wraps the SQLite database. Safe for concurrent use.
type Store struct {
	db         *sql.DB
	logQueries bool
	retention  time.Duration
}

// Open creates/opens the database and applies the schema.
func Open(path string, logQueries bool, retention time.Duration) (*Store, error) {
	db, err := sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(ON)")
	if err != nil {
		return nil, err
	}
	// A single connection avoids SQLITE_BUSY entirely; throughput is plenty
	// for counters and (optional) logging on a small VPS.
	db.SetMaxOpenConns(1)
	s := &Store{db: db, logQueries: logQueries, retention: retention}
	if err := s.schema(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) schema() error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS clients (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL UNIQUE,
			token TEXT NOT NULL UNIQUE,
			created_at INTEGER NOT NULL,
			last_seen INTEGER NOT NULL DEFAULT 0,
			active INTEGER NOT NULL DEFAULT 1
		)`,
		`CREATE TABLE IF NOT EXISTS day_counters (
			day TEXT NOT NULL,
			client_id INTEGER NOT NULL,
			queries INTEGER NOT NULL DEFAULT 0,
			blocked INTEGER NOT NULL DEFAULT 0,
			PRIMARY KEY (day, client_id)
		)`,
		`CREATE TABLE IF NOT EXISTS top_domains (
			day TEXT NOT NULL,
			domain TEXT NOT NULL,
			queries INTEGER NOT NULL DEFAULT 0,
			blocked INTEGER NOT NULL DEFAULT 0,
			PRIMARY KEY (day, domain)
		)`,
		`CREATE TABLE IF NOT EXISTS query_log (
			ts INTEGER NOT NULL,
			client_id INTEGER NOT NULL,
			qname TEXT NOT NULL,
			qtype TEXT NOT NULL,
			blocked INTEGER NOT NULL,
			rcode INTEGER NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_query_log_ts ON query_log (ts)`,
	}
	for _, q := range stmts {
		if _, err := s.db.Exec(q); err != nil {
			return fmt.Errorf("schema: %w", err)
		}
	}
	return nil
}

// Close releases the database.
func (s *Store) Close() error { return s.db.Close() }

func newToken() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// CreateClient registers a new device and returns it with a fresh token.
func (s *Store) CreateClient(name string) (*Client, error) {
	tok, err := newToken()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	res, err := s.db.Exec(
		`INSERT INTO clients (name, token, created_at, last_seen, active) VALUES (?, ?, ?, ?, 1)`,
		name, tok, now.Unix(), now.Unix())
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	return &Client{ID: id, Name: name, Token: tok, CreatedAt: now, LastSeen: now, Active: true}, nil
}

// ListClients returns all clients, newest first.
func (s *Store) ListClients() ([]Client, error) {
	rows, err := s.db.Query(`SELECT id, name, token, created_at, last_seen, active FROM clients ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Client
	for rows.Next() {
		var c Client
		var created, seen int64
		var active int
		if err := rows.Scan(&c.ID, &c.Name, &c.Token, &created, &seen, &active); err != nil {
			return nil, err
		}
		c.CreatedAt = time.Unix(created, 0)
		c.LastSeen = time.Unix(seen, 0)
		c.Active = active == 1
		out = append(out, c)
	}
	return out, rows.Err()
}

// ClientByToken authenticates a per-device DoH token.
func (s *Store) ClientByToken(tok string) (*Client, error) {
	row := s.db.QueryRow(`SELECT id, name, token, created_at, last_seen, active FROM clients WHERE token = ?`, tok)
	return s.scanClient(row)
}

// ClientByName looks a client up by name.
func (s *Store) ClientByName(name string) (*Client, error) {
	row := s.db.QueryRow(`SELECT id, name, token, created_at, last_seen, active FROM clients WHERE name = ?`, name)
	return s.scanClient(row)
}

func (s *Store) scanClient(row *sql.Row) (*Client, error) {
	var c Client
	var created, seen int64
	var active int
	if err := row.Scan(&c.ID, &c.Name, &c.Token, &created, &seen, &active); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	c.CreatedAt = time.Unix(created, 0)
	c.LastSeen = time.Unix(seen, 0)
	c.Active = active == 1
	return &c, nil
}

// DeleteClient removes a device and its counters.
func (s *Store) DeleteClient(id int64) error {
	if _, err := s.db.Exec(`DELETE FROM clients WHERE id = ?`, id); err != nil {
		return err
	}
	_, err := s.db.Exec(`DELETE FROM day_counters WHERE client_id = ?`, id)
	return err
}

// TouchClient updates last_seen only when the presented token matches.
func (s *Store) TouchClient(id int64, tok string) error {
	row := s.db.QueryRow(`SELECT token FROM clients WHERE id = ?`, id)
	var real string
	if err := row.Scan(&real); err != nil {
		return err
	}
	if subtle.ConstantTimeCompare([]byte(real), []byte(tok)) != 1 {
		return errors.New("token mismatch")
	}
	_, err := s.db.Exec(`UPDATE clients SET last_seen = ? WHERE id = ?`, time.Now().Unix(), id)
	return err
}

// RecordQuery bumps daily counters and, when enabled, the query log.
// It never returns an error for stats failures; logging is best-effort.
func (s *Store) RecordQuery(clientID int64, qname, qtype string, blocked bool, rcode int) {
	day := time.Now().UTC().Format("2006-01-02")
	bi := 0
	if blocked {
		bi = 1
	}
	if qname == "" {
		qname = "-"
	}
	_, _ = s.db.Exec(`INSERT INTO day_counters (day, client_id, queries, blocked) VALUES (?, ?, 1, ?)
		ON CONFLICT (day, client_id) DO UPDATE SET queries = queries + 1, blocked = blocked + ?`,
		day, clientID, bi, bi)
	_, _ = s.db.Exec(`INSERT INTO day_counters (day, client_id, queries, blocked) VALUES (?, 0, 1, ?)
		ON CONFLICT (day, client_id) DO UPDATE SET queries = queries + 1, blocked = blocked + ?`,
		day, bi, bi)
	if s.logQueries {
		_, _ = s.db.Exec(`INSERT INTO query_log (ts, client_id, qname, qtype, blocked, rcode) VALUES (?, ?, ?, ?, ?, ?)`,
			time.Now().Unix(), clientID, qname, qtype, bi, rcode)
		_, _ = s.db.Exec(`INSERT INTO top_domains (day, domain, queries, blocked) VALUES (?, ?, 1, ?)
			ON CONFLICT (day, domain) DO UPDATE SET queries = queries + 1, blocked = blocked + ?`,
			day, qname, bi, bi)
	}
}

// Totals returns (queries, blocked) since the given time.
func (s *Store) Totals(since time.Time) (uint64, uint64) {
	row := s.db.QueryRow(`SELECT COALESCE(SUM(queries),0), COALESCE(SUM(blocked),0) FROM day_counters WHERE day >= ?`,
		since.UTC().Format("2006-01-02"))
	var q, b uint64
	_ = row.Scan(&q, &b)
	return q, b
}

// PerDay returns queries/blocked per UTC day since the given time.
func (s *Store) PerDay(since time.Time) ([]DayRow, error) {
	rows, err := s.db.Query(`SELECT day, SUM(queries), SUM(blocked) FROM day_counters WHERE client_id = 0 AND day >= ? GROUP BY day ORDER BY day`,
		since.UTC().Format("2006-01-02"))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DayRow
	for rows.Next() {
		var r DayRow
		if err := rows.Scan(&r.Day, &r.Queries, &r.Blocked); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// DayRow is one day of aggregated counters.
type DayRow struct {
	Day     string `json:"day"`
	Queries uint64 `json:"queries"`
	Blocked uint64 `json:"blocked"`
}

// PerClient returns counters per client since the given time.
func (s *Store) PerClient(since time.Time) ([]ClientRow, error) {
	rows, err := s.db.Query(`SELECT c.id, c.name, c.token, COALESCE(SUM(d.queries),0), COALESCE(SUM(d.blocked),0)
		FROM clients c LEFT JOIN day_counters d ON d.client_id = c.id AND d.day >= ?
		GROUP BY c.id ORDER BY 4 DESC`, since.UTC().Format("2006-01-02"))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ClientRow
	for rows.Next() {
		var r ClientRow
		if err := rows.Scan(&r.ID, &r.Name, &r.Token, &r.Queries, &r.Blocked); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ClientRow aggregates one client's counters.
type ClientRow struct {
	ID      int64  `json:"id"`
	Name    string `json:"name"`
	Token   string `json:"token"`
	Queries uint64 `json:"queries"`
	Blocked uint64 `json:"blocked"`
}

// TopDomains returns the most queried (or blocked) domains since the given time.
func (s *Store) TopDomains(since time.Time, limit int, onlyBlocked bool) ([]DomainRow, error) {
	q := `SELECT domain, SUM(queries), SUM(blocked) FROM top_domains WHERE day >= ?`
	if onlyBlocked {
		q += ` AND blocked > 0`
	}
	q += ` GROUP BY domain ORDER BY 3 DESC LIMIT ?`
	rows, err := s.db.Query(q, since.UTC().Format("2006-01-02"), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DomainRow
	for rows.Next() {
		var r DomainRow
		if err := rows.Scan(&r.Domain, &r.Queries, &r.Blocked); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// DomainRow aggregates one domain's counters.
type DomainRow struct {
	Domain  string `json:"domain"`
	Queries uint64 `json:"queries"`
	Blocked uint64 `json:"blocked"`
}

// RecentLog returns the newest query-log rows.
func (s *Store) RecentLog(limit int) ([]LogRow, error) {
	rows, err := s.db.Query(`SELECT q.ts, q.client_id, COALESCE(c.name, ''), q.qname, q.qtype, q.blocked, q.rcode FROM query_log q LEFT JOIN clients c ON c.id = q.client_id ORDER BY q.ts DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []LogRow
	for rows.Next() {
		var r LogRow
		if err := rows.Scan(&r.TS, &r.ClientID, &r.ClientName, &r.QName, &r.QType, &r.Blocked, &r.RCode); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// LogRow is one entry of the opt-in query log.
type LogRow struct {
	TS         int64  `json:"ts"`
	ClientID   int64  `json:"client_id"`
	ClientName string `json:"client_name"`
	QName      string `json:"qname"`
	QType      string `json:"qtype"`
	Blocked    int    `json:"blocked"`
	RCode      int    `json:"rcode"`
}

// Cleanup deletes expired rows. Call periodically.
func (s *Store) Cleanup() error {
	cutoff := time.Now().Add(-s.retention).Unix()
	if _, err := s.db.Exec(`DELETE FROM query_log WHERE ts < ?`, cutoff); err != nil {
		return err
	}
	dayCutoff := time.Now().UTC().AddDate(0, 0, -int(s.retention.Hours()/24)-1).Format("2006-01-02")
	if _, err := s.db.Exec(`DELETE FROM day_counters WHERE day < ?`, dayCutoff); err != nil {
		return err
	}
	_, err := s.db.Exec(`DELETE FROM top_domains WHERE day < ?`, dayCutoff)
	return err
}

// Loop runs periodic cleanup until ctx is done.
func (s *Store) Loop(done <-chan struct{}) {
	t := time.NewTicker(6 * time.Hour)
	defer t.Stop()
	for {
		select {
		case <-done:
			return
		case <-t.C:
			_ = s.Cleanup()
		}
	}
}
