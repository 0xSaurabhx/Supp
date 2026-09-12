package dns

import (
	"testing"
	"time"

	mdns "github.com/miekg/dns"
)

func TestCacheKeyDistinguishesQTypeAndDO(t *testing.T) {
	mk := func(qtype uint16, do bool) *mdns.Msg {
		m := new(mdns.Msg)
		m.SetQuestion("example.com.", qtype)
		if do {
			m.SetEdns0(1232, true)
		}
		return m
	}
	a := cacheKey(mk(mdns.TypeA, false))
	b := cacheKey(mk(mdns.TypeAAAA, false))
	c := cacheKey(mk(mdns.TypeA, true))
	if a == b || a == c || b == c {
		t.Fatalf("keys collide: %q %q %q", a, b, c)
	}
	if cacheKey(mk(mdns.TypeA, false)) != a {
		t.Fatal("keys must be deterministic")
	}
}

func TestClampTTLs(t *testing.T) {
	m := new(mdns.Msg)
	m.Answer = []mdns.RR{&mdns.A{
		Hdr: mdns.RR_Header{Name: "x.com.", Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 5},
	}}
	got := clampTTLs(m, 60*time.Second, time.Hour)
	if got != 60*time.Second {
		t.Fatalf("min clamp = %v", got)
	}
	if m.Answer[0].Header().Ttl != 60 {
		t.Fatalf("rr ttl = %d", m.Answer[0].Header().Ttl)
	}

	m2 := new(mdns.Msg)
	m2.Answer = []mdns.RR{&mdns.A{
		Hdr: mdns.RR_Header{Name: "x.com.", Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 86400},
	}}
	got2 := clampTTLs(m2, time.Minute, time.Hour)
	if got2 != time.Hour {
		t.Fatalf("max clamp = %v", got2)
	}
}

func TestClampTTLsNegativeUsesSOA(t *testing.T) {
	m := new(mdns.Msg)
	m.Ns = []mdns.RR{&mdns.SOA{
		Hdr:    mdns.RR_Header{Name: "x.com.", Rrtype: mdns.TypeSOA, Class: mdns.ClassINET, Ttl: 900},
		Minttl: 120,
	}}
	got := clampTTLs(m, 30*time.Second, time.Hour)
	if got != 120*time.Second {
		t.Fatalf("soa minttl = %v", got)
	}
}

func TestReplyCachePutGet(t *testing.T) {
	c := newReplyCache(128, time.Minute)
	q := new(mdns.Msg)
	q.SetQuestion("example.com.", mdns.TypeA)
	ans := new(mdns.Msg)
	ans.SetReply(q)
	ans.Answer = []mdns.RR{&mdns.A{
		Hdr: mdns.RR_Header{Name: "example.com.", Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 300},
	}}
	c.put(q, ans, 300*time.Second)

	got, fresh, ok := c.get(q)
	if !ok || !fresh {
		t.Fatalf("get = %v %v", ok, fresh)
	}
	if got.Id != q.Id {
		t.Fatal("msg copy should preserve id after set by caller")
	}
	if got.Answer[0].Header().Ttl != 300 {
		t.Fatalf("ttl = %d", got.Answer[0].Header().Ttl)
	}
	// Mutating the copy must not affect the stored entry.
	got.Answer[0].Header().Ttl = 1
	again, _, _ := c.get(q)
	if again.Answer[0].Header().Ttl != 300 {
		t.Fatal("cache must return copies")
	}
}

func TestCacheLRUEviction(t *testing.T) {
	c := newReplyCache(64, time.Minute) // floor 1024; use small map directly
	c.size = 8
	for i := 0; i < 20; i++ {
		q := new(mdns.Msg)
		q.SetQuestion(qname(i), mdns.TypeA)
		ans := new(mdns.Msg)
		ans.SetReply(q)
		c.put(q, ans, time.Second)
	}
	if len(c.items) > 8 {
		t.Fatalf("cache grew to %d", len(c.items))
	}
}

func qname(i int) string {
	return "q" + string(rune('a'+i%26)) + ".test."
}
