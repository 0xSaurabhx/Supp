package dns

import (
	"sync"
	"time"
)

// Metrics are live in-memory counters plus per-domain top counts.
type Metrics struct {
	mu                                                  sync.Mutex
	started                                             time.Time
	byDomain                                            map[string]*domainCount
	byClient                                            map[int64]*domainCount
	recent                                              []RecentQuery
	blockedTotal, queriesTotal, cachedTotal, staleTotal uint64
}

type domainCount struct {
	queries uint64
	blocked uint64
}

// RecentQuery is one entry of the dashboard's live view (ring of 200).
type RecentQuery struct {
	TS      time.Time `json:"ts"`
	Client  string    `json:"client"`
	QName   string    `json:"qname"`
	QType   string    `json:"qtype"`
	Blocked bool      `json:"blocked"`
	Cached  bool      `json:"cached"`
}

// NewMetrics creates the metrics registry.
func NewMetrics() *Metrics {
	return &Metrics{started: time.Now(), byDomain: map[string]*domainCount{}, byClient: map[int64]*domainCount{}}
}

// Observe records one query handling outcome.
func (m *Metrics) Observe(client string, clientID int64, qname, qtype string, blocked, cached bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.queriesTotal++
	if blocked {
		m.blockedTotal++
	}
	if cached {
		m.cachedTotal++
	}
	if d, ok := m.byDomain[qname]; ok {
		d.queries++
		if blocked {
			d.blocked++
		}
	} else {
		m.byDomain[qname] = &domainCount{queries: 1, blocked: b2u(blocked)}
	}
	if clientID > 0 {
		if d, ok := m.byClient[clientID]; ok {
			d.queries++
			if blocked {
				d.blocked++
			}
		} else {
			m.byClient[clientID] = &domainCount{queries: 1, blocked: b2u(blocked)}
		}
	}
	m.recent = append(m.recent, RecentQuery{TS: time.Now(), Client: client, QName: qname, QType: qtype, Blocked: blocked, Cached: cached})
	if len(m.recent) > 200 {
		// drop the oldest 100 to amortize
		m.recent = append(m.recent[:0], m.recent[100:]...)
	}
}

// ObserveStale counts a serve-stale answer.
func (m *Metrics) ObserveStale() {
	m.mu.Lock()
	m.staleTotal++
	m.mu.Unlock()
}

func b2u(b bool) uint64 {
	if b {
		return 1
	}
	return 0
}

// Snapshot returns dashboard-facing aggregates.
func (m *Metrics) Snapshot() Snapshot {
	m.mu.Lock()
	defer m.mu.Unlock()
	snap := Snapshot{
		Uptime:       time.Since(m.started),
		QueriesTotal: m.queriesTotal,
		BlockedTotal: m.blockedTotal,
		CachedTotal:  m.cachedTotal,
		StaleTotal:   m.staleTotal,
		Top:          make([]TopEntry, 0, len(m.byDomain)),
		Clients:      make([]ClientEntry, 0, len(m.byClient)),
		Recent:       append([]RecentQuery(nil), m.recent...),
	}
	for d, c := range m.byDomain {
		snap.Top = append(snap.Top, TopEntry{Domain: d, Queries: c.queries, Blocked: c.blocked})
	}
	for id, c := range m.byClient {
		snap.Clients = append(snap.Clients, ClientEntry{ClientID: id, Queries: c.queries, Blocked: c.blocked})
	}
	sortTop(snap.Top)
	return snap
}

// Snapshot is a point-in-time view for the dashboard.
type Snapshot struct {
	Uptime       time.Duration `json:"uptime"`
	QueriesTotal uint64        `json:"queries_total"`
	BlockedTotal uint64        `json:"blocked_total"`
	CachedTotal  uint64        `json:"cached_total"`
	StaleTotal   uint64        `json:"stale_total"`
	Top          []TopEntry    `json:"top"`
	Clients      []ClientEntry `json:"clients"`
	Recent       []RecentQuery `json:"recent"`
}

// TopEntry is one per-domain aggregate.
type TopEntry struct {
	Domain  string `json:"domain"`
	Queries uint64 `json:"queries"`
	Blocked uint64 `json:"blocked"`
}

// ClientEntry is one per-client aggregate.
type ClientEntry struct {
	ClientID int64  `json:"client_id"`
	Queries  uint64 `json:"queries"`
	Blocked  uint64 `json:"blocked"`
}

func sortTop(t []TopEntry) {
	// insertion sort is fine for dashboard sizes; keep allocation-free-ish
	for i := 1; i < len(t); i++ {
		for j := i; j > 0 && t[j].Queries > t[j-1].Queries; j-- {
			t[j], t[j-1] = t[j-1], t[j]
		}
	}
}
