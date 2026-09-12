package dns

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	mdns "github.com/miekg/dns"

	"github.com/0xsaurabhx/Supp/internal/filter"
	"github.com/0xsaurabhx/Supp/internal/store"
)

// testUpstream answers A queries from a fixed map; everything else NXDOMAIN.
type testUpstream struct {
	answers map[string][]string
	server  *mdns.Server
	addr    string
}

func newTestUpstream(t *testing.T, answers map[string][]string) *testUpstream {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := pc.LocalAddr().String()
	tu := &testUpstream{answers: answers, addr: addr}
	srv := &mdns.Server{
		PacketConn: pc,
		Handler:    mdns.HandlerFunc(tu.serve),
	}
	go func() { _ = srv.ActivateAndServe() }()
	tu.server = srv
	t.Cleanup(func() { _ = srv.Shutdown() })
	return tu
}

func (tu *testUpstream) serve(w mdns.ResponseWriter, r *mdns.Msg) {
	m := new(mdns.Msg)
	m.SetReply(r)
	q := r.Question[0]
	name := strings.ToLower(strings.TrimSuffix(q.Name, "."))
	if q.Qtype == mdns.TypeA {
		if ips, ok := tu.answers[name]; ok {
			for _, ip := range ips {
				m.Answer = append(m.Answer, &mdns.A{
					Hdr: mdns.RR_Header{Name: q.Name, Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 300},
					A:   net.ParseIP(ip),
				})
			}
			_ = w.WriteMsg(m)
			return
		}
		if cname, ok := tu.answers["cname:"+name]; ok {
			m.Answer = append(m.Answer, &mdns.CNAME{
				Hdr:    mdns.RR_Header{Name: q.Name, Rrtype: mdns.TypeCNAME, Class: mdns.ClassINET, Ttl: 300},
				Target: mdns.Fqdn(cname[0]),
			})
			_ = w.WriteMsg(m)
			return
		}
	}
	m.SetRcode(r, mdns.RcodeNameError)
	_ = w.WriteMsg(m)
}

func selfSignedFor(t *testing.T, host string) *tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: host},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{host},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

func freePorts(t *testing.T, n int) []string {
	t.Helper()
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		addr := ln.Addr().String()
		ln.Close()
		out = append(out, addr)
	}
	return out
}

func newTestServer(t *testing.T, answers map[string][]string) (*Server, *store.Store, string) {
	t.Helper()
	tu := newTestUpstream(t, answers)
	ports := freePorts(t, 2)
	st, err := store.Open(t.TempDir()+"/test.db", true, 720*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	eng := filter.NewEngine(t.TempDir(), nil,
		[]string{"allowed.example.com"},
		[]string{"blocked.example.com", "tracker.cloaked.net"}, 0)
	cert := selfSignedFor(t, "127.0.0.1")
	srv, err := NewServer(Config{
		ListenPlain:  ports[0],
		ListenDoH:    ports[1],
		DoHCert:      cert,
		PerDeviceDoH: true,
		Upstreams:    []string{"udp://" + tu.addr},
		Bootstrap:    []string{"9.9.9.9"},
		Timeout:      2 * time.Second,
		CacheSize:    1024,
		CacheMinTTL:  10 * time.Second,
		CacheMaxTTL:  time.Hour,
		Blocker:      eng,
		Store:        st,
	}, testLogger(t))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = srv.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	waitForListener(t, ports[0])
	return srv, st, ports[0]
}

// waitForListener polls until the server's TCP listener accepts (all
// listeners bind before Run proceeds past setup).
func waitForListener(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			c.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("server listener %s never came up", addr)
}

func testLogger(t *testing.T) *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

func TestPipelineBlockAllowResolve(t *testing.T) {
	_, _, plain := newTestServer(t, map[string][]string{
		"ok.example.com": {"1.2.3.4"},
	})
	ask := func(name string, qtype uint16) *mdns.Msg {
		m := new(mdns.Msg)
		m.SetQuestion(mdns.Fqdn(name), qtype)
		c := &mdns.Client{Net: "udp", Timeout: 2 * time.Second}
		resp, _, err := c.Exchange(m, plain)
		if err != nil {
			t.Fatalf("exchange %s: %v", name, err)
		}
		return resp
	}

	// Resolved.
	r := ask("ok.example.com", mdns.TypeA)
	if r.Rcode != mdns.RcodeSuccess || len(r.Answer) != 1 {
		t.Fatalf("resolve: rcode=%d answers=%d", r.Rcode, len(r.Answer))
	}
	if r.Answer[0].(*mdns.A).A.String() != "1.2.3.4" {
		t.Fatalf("answer = %v", r.Answer[0])
	}

	// Blocked via denylist → 0.0.0.0.
	b := ask("blocked.example.com", mdns.TypeA)
	if b.Rcode != mdns.RcodeSuccess || len(b.Answer) != 1 {
		t.Fatalf("block: rcode=%d answers=%d", b.Rcode, len(b.Answer))
	}
	if a := b.Answer[0].(*mdns.A).A.String(); a != "0.0.0.0" {
		t.Fatalf("block answer = %s, want 0.0.0.0", a)
	}

	// Blocked AAAA → ::.
	b6 := ask("blocked.example.com", mdns.TypeAAAA)
	if len(b6.Answer) != 1 {
		t.Fatal("expected AAAA block answer")
	}
	if a := b6.Answer[0].(*mdns.AAAA).AAAA.String(); a != "::" {
		t.Fatalf("block aaaa = %s", a)
	}

	// NXDOMAIN for other names.
	nx := ask("missing.example.com", mdns.TypeA)
	if nx.Rcode != mdns.RcodeNameError {
		t.Fatalf("nxdomain: rcode=%d", nx.Rcode)
	}
}

func TestCNAMEUncloaking(t *testing.T) {
	_, _, plain := newTestServer(t, map[string][]string{
		"cname:news.site.com": {"tracker.cloaked.net"},
	})
	m := new(mdns.Msg)
	m.SetQuestion("news.site.com.", mdns.TypeA)
	c := &mdns.Client{Net: "udp", Timeout: 2 * time.Second}
	resp, _, err := c.Exchange(m, plain)
	if err != nil {
		t.Fatal(err)
	}
	// The CNAME target is a blocked tracker: answer must come back empty
	// (NOERROR/0 answers), never carrying the tracker chain.
	if len(resp.Answer) != 0 {
		t.Fatalf("uncloak failed, answers: %v", resp.Answer)
	}
}

func TestCacheHits(t *testing.T) {
	srv, _, plain := newTestServer(t, map[string][]string{
		"cached.example.com": {"9.9.9.9"},
	})
	m := new(mdns.Msg)
	m.SetQuestion("cached.example.com.", mdns.TypeA)
	c := &mdns.Client{Net: "udp", Timeout: 2 * time.Second}
	if _, _, err := c.Exchange(m, plain); err != nil {
		t.Fatal(err)
	}
	got, fresh, ok := srv.cache.get(m)
	if !ok || !fresh {
		t.Fatal("expected fresh cache entry")
	}
	if len(got.Answer) != 1 || got.Answer[0].(*mdns.A).A.String() != "9.9.9.9" {
		t.Fatalf("cached answer = %v", got.Answer)
	}
}

func TestDoHAndPerDeviceToken(t *testing.T) {
	srv, st, plain := newTestServer(t, map[string][]string{
		"ok.example.com": {"5.6.7.8"},
	})
	_ = plain

	cl, err := st.CreateClient("pixel")
	if err != nil {
		t.Fatal(err)
	}
	// find the DoH port
	dohAddr := srv.cfg.ListenDoH
	httpCl := &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
		Timeout:   5 * time.Second,
	}
	q := new(mdns.Msg)
	q.SetQuestion("ok.example.com.", mdns.TypeA)
	wire, _ := q.Pack()
	url := fmt.Sprintf("https://%s/dns/%s", dohAddr, cl.Token)
	req, _ := http.NewRequest(http.MethodPost, url, strings.NewReader(string(wire)))
	req.Header.Set("Content-Type", "application/dns-message")
	resp, err := httpCl.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("doh status = %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	out := new(mdns.Msg)
	if err := out.Unpack(body); err != nil {
		t.Fatal(err)
	}
	if len(out.Answer) != 1 || out.Answer[0].(*mdns.A).A.String() != "5.6.7.8" {
		t.Fatalf("doh answer = %v", out.Answer)
	}

	// Bad token must be forbidden.
	badURL := fmt.Sprintf("https://%s/dns/deadbeefdeadbeef", dohAddr)
	req2, _ := http.NewRequest(http.MethodPost, badURL, strings.NewReader(string(wire)))
	req2.Header.Set("Content-Type", "application/dns-message")
	resp2, err := httpCl.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusForbidden {
		t.Fatalf("bad token status = %d, want 403", resp2.StatusCode)
	}

	// GET with base64url works too.
	getURL := fmt.Sprintf("https://%s/dns/%s?dns=%s", dohAddr, cl.Token,
		base64.RawURLEncoding.EncodeToString(wire))
	resp3, err := httpCl.Get(getURL)
	if err != nil {
		t.Fatal(err)
	}
	resp3.Body.Close()
	if resp3.StatusCode != 200 {
		t.Fatalf("doh GET status = %d", resp3.StatusCode)
	}
}
