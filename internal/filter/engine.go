package filter

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type listMeta struct {
	etag    string
	lastMod time.Time
}

var (
	defaultBlockA4    = netip.MustParseAddr("0.0.0.0")
	defaultBlockAAAA6 = netip.MustParseAddr("::")
)

// Sources maps list name -> parsed entry count (-1 when the fetch failed).
type Sources map[string]int

// Engine evaluates a query domain against the active block/allow sets.
// Safe for concurrent use; Refresh swaps in new sets atomically.
type Engine struct {
	mu      sync.RWMutex
	blocked *DomainSet
	allowed *DomainSet
	metas   map[string]*listMeta
	counts  Sources
	lastErr string
	lastTry time.Time

	lists        []ListSpec
	allow        []string
	deny         []string
	respA4       atomic.Pointer[netip.Addr]
	respA6       atomic.Pointer[netip.Addr]
	blockIPv6    bool
	client       *http.Client
	dataDir      string
	refreshEvery time.Duration

	hitsBlock atomic.Uint64
	hitsAllow atomic.Uint64
	hitsPass  atomic.Uint64
}

// ListSpec identifies one blocklist source.
type ListSpec struct {
	Name   string
	URL    string
	Format string
}

// SourceStatus is refresh state for one list, shown on the dashboard.
type SourceStatus struct {
	Name    string    `json:"name"`
	URL     string    `json:"url"`
	Entries int       `json:"entries"`
	Fetched time.Time `json:"fetched"`
	ETag    string    `json:"etag,omitempty"`
	Error   string    `json:"error,omitempty"`
}

// Stats summarizes filter state for the dashboard.
type Stats struct {
	BlockedDomains int            `json:"blocked_domains"`
	AllowedDomains int            `json:"allowed_domains"`
	HitsBlock      uint64         `json:"hits_block"`
	HitsAllow      uint64         `json:"hits_allow"`
	LastRefresh    time.Time      `json:"last_refresh"`
	LastError      string         `json:"last_error,omitempty"`
	Sources        []SourceStatus `json:"sources"`
}

// EngineOption configures an Engine.
type EngineOption func(*Engine)

// WithHTTPClient overrides the HTTP client used for list downloads.
func WithHTTPClient(c *http.Client) EngineOption {
	return func(e *Engine) { e.client = c }
}

// NewEngine builds an Engine from list specs plus inline allow/deny entries.
func NewEngine(dataDir string, lists []ListSpec, allow, deny []string, refreshEvery time.Duration, opts ...EngineOption) *Engine {
	e := &Engine{
		blocked:      NewDomainSet(),
		allowed:      NewDomainSet(),
		metas:        make(map[string]*listMeta, len(lists)),
		lists:        lists,
		allow:        allow,
		deny:         deny,
		client:       &http.Client{Timeout: 60 * time.Second},
		dataDir:      dataDir,
		refreshEvery: refreshEvery,
	}
	def4 := defaultBlockA4
	def6 := defaultBlockAAAA6
	e.respA4.Store(&def4)
	e.respA6.Store(&def6)
	for _, o := range opts {
		o(e)
	}
	for _, d := range deny {
		e.blocked.Add(d)
	}
	for _, a := range allow {
		e.allowed.Add(a)
	}
	return e
}

// blockIPs returns the addresses answered for blocked queries.
func (e *Engine) blockIPs() (netip.Addr, netip.Addr) {
	a4, a6 := defaultBlockA4, defaultBlockAAAA6
	if a := e.respA4.Load(); a != nil {
		a4 = *a
	}
	if a := e.respA6.Load(); a != nil {
		a6 = *a
	}
	return a4, a6
}

// Check reports whether the domain must be blocked. Allowlist wins.
func (e *Engine) Check(domain string) bool {
	if e.allowed.Has(domain) {
		e.hitsAllow.Add(1)
		return false
	}
	if e.blocked.Has(domain) {
		e.hitsBlock.Add(1)
		return true
	}
	e.hitsPass.Add(1)
	return false
}

// SetResponseIP overrides the addresses answered for blocked domains.
// Either argument may be empty to keep the current value.
func (e *Engine) SetResponseIP(a4, a6 string) {
	if a4 != "" {
		if a, err := netip.ParseAddr(a4); err == nil && a.IsValid() {
			e.respA4.Store(&a)
		}
	}
	if a6 != "" {
		if a, err := netip.ParseAddr(a6); err == nil && a.IsValid() {
			e.respA6.Store(&a)
		}
	}
}

// BlockIPv4 returns the A address used for blocked answers.
func (e *Engine) BlockIPv4() netip.Addr {
	a, _ := e.blockIPs()
	return a
}

// BlockIPv6 returns the AAAA address used for blocked answers.
func (e *Engine) BlockIPv6() netip.Addr {
	_, a := e.blockIPs()
	return a
}

// Stats returns a dashboard snapshot.
func (e *Engine) Stats() Stats {
	e.mu.RLock()
	defer e.mu.RUnlock()
	st := Stats{
		BlockedDomains: e.blocked.Len(),
		AllowedDomains: e.allowed.Len(),
		HitsBlock:      e.hitsBlock.Load(),
		HitsAllow:      e.hitsAllow.Load(),
		LastRefresh:    e.lastTry,
		LastError:      e.lastErr,
		Sources:        make([]SourceStatus, 0, len(e.lists)),
	}
	for _, spec := range e.lists {
		s := SourceStatus{Name: spec.Name, URL: spec.URL, Fetched: e.lastTry}
		if c, ok := e.counts[spec.Name]; ok {
			s.Entries = c
			if c < 0 {
				s.Error = "last fetch failed"
			}
		}
		if m := e.metas[spec.Name]; m != nil {
			s.ETag = m.etag
		}
		st.Sources = append(st.Sources, s)
	}
	return st
}

// Refresh downloads stale lists and atomically swaps in the new sets.
// A source that fails keeps its previous entries: an outage must never
// widen what is blocked less than before, and never unblock domains that
// were blocked. Returns the first error, if any.
func (e *Engine) Refresh(ctx context.Context) error {
	e.mu.Lock()
	if time.Since(e.lastTry) < 5*time.Second {
		e.mu.Unlock()
		return nil
	}
	e.lastTry = time.Now()
	e.mu.Unlock()

	specs := e.snapshotSpecs()
	total := 0
	newBlocked := NewDomainSet()
	newAllowed := NewDomainSet()
	newMetas := make(map[string]*listMeta, len(specs))
	counts := make(Sources, len(specs))
	var firstErr error

	for _, spec := range specs {
		data, ok := e.fetch(ctx, spec)
		if !ok {
			counts[spec.Name] = -1
			if firstErr == nil {
				firstErr = fmt.Errorf("fetch %s failed", spec.Name)
			}
			// Fall back to the cached copy from the last good run.
			if cached, err := os.ReadFile(e.cachePath(spec)); err == nil {
				data, ok = cached, true
			}
		}
		if !ok {
			continue
		}
		n := e.parseInto(spec, data, newBlocked, newAllowed)
		counts[spec.Name] = n
		total += n
	}
	_ = total

	e.mu.RLock()
	allow, deny := e.allow, e.deny
	e.mu.RUnlock()
	for _, d := range deny {
		newBlocked.Add(d)
	}
	for _, a := range allow {
		newAllowed.Add(a)
	}

	// If any source failed without a usable cache, union the old blocked set
	// into the new one so nothing silently becomes unblocked.
	for _, spec := range specs {
		if counts[spec.Name] == -1 {
			e.mu.RLock()
			old := e.blocked
			oldAllowed := e.allowed
			e.mu.RUnlock()
			old.Each(func(d string) { newBlocked.Add(d) })
			oldAllowed.Each(func(d string) { newAllowed.Add(d) })
			break
		}
	}

	e.mu.Lock()
	// Carry over conditional-request metadata for sources that were served
	// from cache (304 or fallback) so their ETags survive the swap.
	for _, spec := range specs {
		if newMetas[spec.Name] == nil {
			if m := e.metas[spec.Name]; m != nil {
				newMetas[spec.Name] = m
			}
		}
	}
	e.blocked = newBlocked
	e.allowed = newAllowed
	e.counts = counts
	e.metas = newMetas
	if firstErr != nil {
		e.lastErr = firstErr.Error()
	} else {
		e.lastErr = ""
	}
	e.mu.Unlock()
	return firstErr
}

func (e *Engine) snapshotSpecs() []ListSpec {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return append([]ListSpec(nil), e.lists...)
}

func (e *Engine) parseInto(spec ListSpec, data []byte, blocked, allowed *DomainSet) int {
	pl, err := Parse(strings.NewReader(string(data)), spec.Format)
	if err != nil {
		return 0
	}
	n := 0
	for _, d := range pl.Blocked {
		if blocked.Add(d) {
			n++
		}
	}
	for _, d := range pl.Allowed {
		allowed.Add(d)
	}
	return n
}

// fetch downloads one list, updating per-list conditional-request metadata.
func (e *Engine) fetch(ctx context.Context, spec ListSpec) ([]byte, bool) {
	if !ValidURL(spec.URL) {
		b, err := os.ReadFile(spec.URL)
		return b, err == nil
	}
	e.mu.RLock()
	meta := e.metas[spec.Name]
	etag, lastMod := "", time.Time{}
	if meta != nil {
		etag, lastMod = meta.etag, meta.lastMod
	}
	e.mu.RUnlock()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, spec.URL, nil)
	if err != nil {
		return nil, false
	}
	req.Header.Set("User-Agent", "supp/1.0 (+https://github.com/0xsaurabhx/Supp)")
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	if !lastMod.IsZero() {
		req.Header.Set("If-Modified-Since", lastMod.UTC().Format(http.TimeFormat))
	}
	resp, err := e.client.Do(req)
	if err != nil {
		return nil, false
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusNotModified:
		if b, err := os.ReadFile(e.cachePath(spec)); err == nil {
			return b, true
		}
		return nil, false
	case http.StatusOK:
		// continue below
	default:
		return nil, false
	}

	b, err := io.ReadAll(io.LimitReader(resp.Body, 256<<20))
	if err != nil {
		return nil, false
	}
	_ = os.MkdirAll(filepath.Dir(e.cachePath(spec)), 0o750)
	_ = os.WriteFile(e.cachePath(spec), b, 0o600)

	nm := &listMeta{}
	if v := resp.Header.Get("ETag"); v != "" {
		nm.etag = v
	}
	if v := resp.Header.Get("Last-Modified"); v != "" {
		if t, perr := http.ParseTime(v); perr == nil {
			nm.lastMod = t
		}
	}
	e.mu.Lock()
	if e.metas == nil {
		e.metas = make(map[string]*listMeta)
	}
	e.metas[spec.Name] = nm
	e.mu.Unlock()
	return b, true
}

func (e *Engine) cachePath(spec ListSpec) string {
	safe := strings.NewReplacer("/", "_", ":", "_", "?", "_", "&", "_").Replace(spec.URL)
	return filepath.Join(e.dataDir, "lists", safe+".cache")
}

// Loop refreshes lists periodically until ctx is cancelled.
func (e *Engine) Loop(ctx context.Context) {
	if e.refreshEvery <= 0 {
		return
	}
	t := time.NewTimer(e.refreshEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			_ = e.Refresh(context.WithoutCancel(ctx))
			t.Reset(e.refreshEvery)
		}
	}
}
