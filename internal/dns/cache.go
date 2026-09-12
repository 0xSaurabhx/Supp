package dns

import (
	"container/list"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	mdns "github.com/miekg/dns"
)

// cacheEntry stores a fully post-processed message ready to serve.
type cacheEntry struct {
	msg   *mdns.Msg
	valid time.Time // fresh until
	stale time.Time // serve-stale until
}

// replyCache is an LRU with TTL and a serve-stale window.
type replyCache struct {
	mu       sync.Mutex
	size     int
	staleFor time.Duration
	items    map[string]*list.Element
	order    *list.List

	hits   atomic.Uint64
	misses atomic.Uint64
	stales atomic.Uint64
}

func newReplyCache(size int, staleFor time.Duration) *replyCache {
	if size < 1024 {
		size = 1024
	}
	return &replyCache{
		size:     size,
		staleFor: staleFor,
		items:    make(map[string]*list.Element, size/4),
		order:    list.New(),
	}
}

func cacheKey(q *mdns.Msg) string {
	do := 0
	if q.IsEdns0() != nil && q.IsEdns0().Do() {
		do = 1
	}
	name := strings.ToLower(q.Question[0].Name)
	return name + "|" + mdns.Type(q.Question[0].Qtype).String() + "|" + string(rune('0'+do))
}

// get returns a copy of the cached message. fresh=false means a stale entry
// was served (all upstreams must be down for callers to use it).
func (c *replyCache) get(q *mdns.Msg) (*mdns.Msg, bool, bool) {
	key := cacheKey(q)
	c.mu.Lock()
	el, ok := c.items[key]
	if !ok {
		c.mu.Unlock()
		c.misses.Add(1)
		return nil, false, false
	}
	c.order.MoveToFront(el)
	e := el.Value.(*entryWrap).e
	now := time.Now()
	if now.Before(e.valid) {
		c.mu.Unlock()
		c.hits.Add(1)
		return e.msg.Copy(), true, true
	}
	if now.Before(e.stale) {
		c.mu.Unlock()
		c.stales.Add(1)
		return e.msg.Copy(), false, true
	}
	c.order.Remove(el)
	delete(c.items, key)
	c.mu.Unlock()
	c.misses.Add(1)
	return nil, false, false
}

// put stores a message; ttfresh is how long it stays authoritative.
func (c *replyCache) put(q *mdns.Msg, m *mdns.Msg, ttfresh time.Duration) {
	key := cacheKey(q)
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.items[key]; ok {
		c.order.Remove(el)
		delete(c.items, key)
	}
	if len(c.items) >= c.size {
		if oldest := c.order.Back(); oldest != nil {
			delete(c.items, oldest.Value.(*entryWrap).key)
			c.order.Remove(oldest)
		}
	}
	el := c.order.PushFront(&entryWrap{key: key, e: &cacheEntry{
		msg:   m,
		valid: now.Add(ttfresh),
		stale: now.Add(ttfresh + c.staleFor),
	}})
	c.items[key] = el
}

type entryWrap struct {
	key string
	e   *cacheEntry
}

func (w *entryWrap) keyOf() string { return w.key }

// clampTTLs normalizes all record TTLs to one clamped value and returns it.
func clampTTLs(m *mdns.Msg, min, max time.Duration) time.Duration {
	if min <= 0 {
		min = 30 * time.Second
	}
	if max <= 0 || max < min {
		max = 24 * time.Hour
	}
	base := time.Duration(0)
	for _, rr := range m.Answer {
		if rr.Header().Ttl > 0 {
			if base == 0 || time.Duration(rr.Header().Ttl)*time.Second < base {
				base = time.Duration(rr.Header().Ttl) * time.Second
			}
		}
	}
	if base == 0 {
		// Negative answers: fall back to SOA minimum from the authority section.
		for _, rr := range m.Ns {
			if soa, ok := rr.(*mdns.SOA); ok {
				base = time.Duration(soa.Minttl) * time.Second
				break
			}
		}
	}
	if base == 0 {
		base = 300 * time.Second
	}
	if base < min {
		base = min
	}
	if base > max {
		base = max
	}
	ttl := uint32(base / time.Second)
	for _, rr := range append(append(append([]mdns.RR{}, m.Answer...), m.Ns...), m.Extra...) {
		if _, isOPT := rr.(*mdns.OPT); !isOPT {
			rr.Header().Ttl = ttl
		}
	}
	return base
}
