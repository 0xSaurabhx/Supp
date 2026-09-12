// Package dns implements the Supp resolver core: caching, upstream
// selection with failover, blocking pipeline and encrypted transports.
package dns

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	mdns "github.com/miekg/dns"
	"golang.org/x/net/idna"
)

var errNoUpstream = errors.New("all upstreams failed")

// upstreamKind classifies an upstream URL scheme.
type upstreamKind int

const (
	kindUDP upstreamKind = iota
	kindTCP
	kindDoT
	kindDoH
)

// upstream is one configured resolver.
type upstream struct {
	url    string
	kind   upstreamKind
	host   string // hostname or IP (no port)
	port   string
	path   string // DoH path
	weight int

	healthy  atomic.Bool
	browser  atomic.Bool // set when served via browser-fingerprint fallback
	inflight atomic.Int64
	latency  atomic.Int64 // EMA in microseconds
	fails    atomic.Int64 // consecutive failures

	addrCache  atomic.Pointer[string] // resolved "ip:port" for DoT/UDP/TCP
	tlsConf    *tls.Config
	httpClient *http.Client
	dialer     *net.Dialer
}

// Pool manages upstreams, health and queries.
type Pool struct {
	upstreams  []*upstream
	bootstrap  []string
	timeout    time.Duration
	refreshInt time.Duration

	browserHeader atomic.Pointer[string] // User-Agent for DoH
	browserPool   *BrowserPool

	resolver   *net.Resolver
	browserMux sync.Mutex
	browserOn  bool

	checkStop chan struct{}
	stopped   sync.WaitGroup
}

// PoolOption configures a Pool.
type PoolOption func(*Pool)

// WithBrowserUpstream adds a browser-fingerprint DoH transport used only
// when every configured upstream is unhealthy.
func WithBrowserUpstream(p *BrowserPool) PoolOption {
	return func(pl *Pool) {
		pl.browserPool = p
		pl.browserOn = p != nil
	}
}

// NewPool dials nothing yet; it prepares transports from raw URLs.
func NewPool(urls []string, weights []int, bootstrap []string, timeout time.Duration, opts ...PoolOption) (*Pool, error) {
	if len(urls) == 0 {
		return nil, errNoUpstream
	}
	p := &Pool{
		bootstrap:  bootstrap,
		timeout:    timeout,
		refreshInt: 5 * time.Minute,
		checkStop:  make(chan struct{}),
		resolver:   &net.Resolver{PreferGo: true},
	}
	for i, raw := range urls {
		u, err := newUpstream(raw, weightAt(weights, i))
		if err != nil {
			return nil, fmt.Errorf("upstream %q: %w", raw, err)
		}
		p.upstreams = append(p.upstreams, u)
	}
	for _, o := range opts {
		o(p)
	}
	return p, nil
}

func weightAt(ws []int, i int) int {
	if i < len(ws) && ws[i] > 0 {
		return ws[i]
	}
	return 1
}

func newUpstream(raw string, weight int) (*upstream, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	up := &upstream{url: raw, weight: weight}
	up.healthy.Store(true)
	switch strings.ToLower(u.Scheme) {
	case "udp":
		up.kind = kindUDP
		up.host = u.Hostname()
		up.port = portOr(u.Port(), "53")
	case "tcp":
		up.kind = kindTCP
		up.host = u.Hostname()
		up.port = portOr(u.Port(), "53")
	case "dot", "tls":
		up.kind = kindDoT
		up.host = u.Hostname()
		up.port = portOr(u.Port(), "853")
	case "doh", "https":
		up.kind = kindDoH
		up.host = u.Hostname()
		up.port = portOr(u.Port(), "443")
		up.path = u.Path
		if up.path == "" {
			up.path = "/dns-query"
		}
	default:
		return nil, fmt.Errorf("unsupported scheme %q", u.Scheme)
	}
	if up.host == "" {
		return nil, errors.New("missing host")
	}
	if isIP(up.host) {
		ip := up.host
		a := net.JoinHostPort(ip, up.port)
		up.addrCache.Store(&a)
	}
	return up, nil
}

func portOr(p, def string) string {
	if p != "" {
		return p
	}
	return def
}

func isIP(s string) bool {
	return net.ParseIP(s) != nil
}

// dialAddr returns a dialable "ip:port", resolving via bootstrap servers
// when the host is a name. Result is cached on the upstream.
func (p *Pool) dialAddr(ctx context.Context, u *upstream) (string, error) {
	if a := u.addrCache.Load(); a != nil {
		return *a, nil
	}
	ips, err := p.resolveBootstrap(ctx, u.host)
	if err != nil || len(ips) == 0 {
		return "", fmt.Errorf("resolve %s: %v", u.host, err)
	}
	a := net.JoinHostPort(ips[0].String(), u.port)
	u.addrCache.Store(&a)
	return a, nil
}

// resolveBootstrap resolves host using the configured bootstrap resolvers.
func (p *Pool) resolveBootstrap(ctx context.Context, host string) ([]net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}, nil
	}
	var lastErr error
	for _, bs := range p.bootstrap {
		m := new(mdns.Msg)
		m.SetQuestion(mdns.Fqdn(host), mdns.TypeA)
		c := &mdns.Client{Net: "udp", Timeout: 2 * time.Second}
		in, _, err := c.ExchangeContext(ctx, m, net.JoinHostPort(bs, "53"))
		if err != nil {
			lastErr = err
			continue
		}
		var ips []net.IP
		for _, rr := range in.Answer {
			if a, ok := rr.(*mdns.A); ok {
				ips = append(ips, a.A)
			}
		}
		if len(ips) > 0 {
			return ips, nil
		}
	}
	if lastErr == nil {
		lastErr = errors.New("no bootstrap answered")
	}
	return nil, lastErr
}

// tlsConfig builds (and caches) the TLS configuration for encrypted kinds.
func (u *upstream) tlsConfig(protos []string) *tls.Config {
	if u.tlsConf != nil {
		return u.tlsConf
	}
	u.tlsConf = &tls.Config{
		ServerName: u.host,
		NextProtos: protos,
		MinVersion: tls.VersionTLS12,
	}
	return u.tlsConf
}

// httpClient builds the DoH client lazily with h2 and our dialer.
func (p *Pool) httpClient(u *upstream) *http.Client {
	if u.httpClient != nil {
		return u.httpClient
	}
	dialer := &net.Dialer{Timeout: p.timeout}
	t := &http.Transport{
		TLSClientConfig:     u.tlsConfig([]string{"h2", "http/1.1"}),
		ForceAttemptHTTP2:   true,
		IdleConnTimeout:     90 * time.Second,
		DialContext:         p.dialContextFor(u, dialer),
		MaxIdleConns:        8,
		MaxIdleConnsPerHost: 4,
	}
	u.httpClient = &http.Client{Transport: t, Timeout: p.timeout}
	return u.httpClient
}

// dialContextFor returns a DialContext that pins dials to the bootstrap-
// resolved address, avoiding the system resolver for upstream hosts.
func (p *Pool) dialContextFor(u *upstream, d *net.Dialer) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		want := addr
		// Only pin when addr host equals the upstream host (not proxies).
		host, port, err := net.SplitHostPort(addr)
		if err == nil && strings.EqualFold(host, u.host) {
			if a, derr := p.dialAddr(ctx, u); derr == nil {
				want = net.JoinHostPort(hostFromAddr(a), port)
			}
		}
		return d.DialContext(ctx, network, want)
	}
}

func hostFromAddr(addr string) string {
	h, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return h
}

// exchange sends one message to this upstream.
func (p *Pool) exchange(ctx context.Context, u *upstream, m *mdns.Msg) (*mdns.Msg, error) {
	u.inflight.Add(1)
	defer u.inflight.Add(-1)

	start := time.Now()
	var resp *mdns.Msg
	var err error
	switch u.kind {
	case kindUDP:
		resp, err = p.exchStreamOrPacket(ctx, u, m, "udp")
	case kindTCP:
		resp, err = p.exchStreamOrPacket(ctx, u, m, "tcp")
	case kindDoT:
		resp, err = p.exchDoT(ctx, u, m)
	case kindDoH:
		resp, err = p.exchDoH(ctx, u, m)
	default:
		err = errNoUpstream
	}
	elapsed := time.Since(start)
	if err != nil {
		u.fails.Add(1)
		if u.fails.Load() >= 2 {
			u.healthy.Store(false)
		}
		return nil, err
	}
	u.fails.Store(0)
	u.healthy.Store(true)
	us := elapsed.Microseconds()
	old := u.latency.Load()
	if old == 0 {
		u.latency.Store(us)
	} else {
		u.latency.Store((old*3 + us) / 4) // EMA
	}
	return resp, nil
}

func (p *Pool) exchStreamOrPacket(ctx context.Context, u *upstream, m *mdns.Msg, net_ string) (*mdns.Msg, error) {
	addr, err := p.dialAddr(ctx, u)
	if err != nil {
		return nil, err
	}
	d := net.Dialer{Timeout: p.timeout}
	conn, err := d.DialContext(ctx, net_, addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	client := &mdns.Client{Net: net_, UDPSize: 4096, Timeout: p.timeout}
	resp, _, err := client.ExchangeWithConn(m, &mdns.Conn{Conn: conn})
	return resp, err
}

func (p *Pool) exchDoT(ctx context.Context, u *upstream, m *mdns.Msg) (*mdns.Msg, error) {
	addr, err := p.dialAddr(ctx, u)
	if err != nil {
		return nil, err
	}
	d := (&tls.Dialer{NetDialer: &net.Dialer{Timeout: p.timeout}, Config: u.tlsConfig([]string{"dot"})})
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	client := &mdns.Client{Net: "tcp", Timeout: p.timeout}
	resp, _, err := client.ExchangeWithConn(m, &mdns.Conn{Conn: conn})
	if err == nil && resp == nil {
		err = errNoUpstream
	}
	return resp, err
}

func (p *Pool) exchDoH(ctx context.Context, u *upstream, m *mdns.Msg) (*mdns.Msg, error) {
	wire, err := m.Pack()
	if err != nil {
		return nil, err
	}
	scheme := "https://"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, scheme+u.host+":"+u.port+u.path, strings.NewReader(string(wire)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	if u.browserMode() {
		return p.browserDoH(ctx, u, wire)
	}
	resp, err := p.httpClient(u).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("doh status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return nil, err
	}
	out := new(mdns.Msg)
	if err := out.Unpack(body); err != nil {
		return nil, err
	}
	return out, nil
}

func (u *upstream) browserMode() bool { return false } // browser mode only set via Pool.Query fallback

// Select returns healthy upstreams ordered for the next query: least
// in-flight first, then best EMA latency, then weight.
func (p *Pool) Select() []*upstream {
	out := make([]*upstream, 0, len(p.upstreams))
	for _, u := range p.upstreams {
		if u.healthy.Load() {
			out = append(out, u)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		ii, jj := out[i].inflight.Load(), out[j].inflight.Load()
		if ii != jj {
			return ii < jj
		}
		li, lj := out[i].latency.Load(), out[j].latency.Load()
		if li != lj {
			return li < lj
		}
		return out[i].weight > out[j].weight
	})
	if len(out) == 0 {
		// All degraded: try everything anyway rather than fail.
		out = append(out, p.upstreams...)
	}
	return out
}

// Query sends m to the best upstream, failing over up to three tries.
func (p *Pool) Query(ctx context.Context, m *mdns.Msg) (*mdns.Msg, error) {
	candidates := p.Select()
	n := 3
	if len(candidates) < n {
		n = len(candidates)
	}
	var lastErr error
	for i := 0; i < n; i++ {
		u := candidates[i]
		resp, err := p.exchange(ctx, u, m)
		if err == nil {
			return resp, nil
		}
		lastErr = err
		// Last resort: browser-fingerprint upstream.
		if i == n-1 && p.browserPool != nil {
			u.browser.Store(true)
			if resp, berr := p.browserDoH(ctx, u, mustPack(m)); berr == nil {
				u.healthy.Store(true)
				return resp, nil
			}
		}
	}
	if lastErr == nil {
		lastErr = errNoUpstream
	}
	return nil, lastErr
}

func mustPack(m *mdns.Msg) []byte {
	b, err := m.Pack()
	if err != nil {
		return nil
	}
	return b
}

// Start launches health probes and address refresh loops.
func (p *Pool) Start() {
	p.stopped.Add(1)
	go func() {
		defer p.stopped.Done()
		probe := time.NewTicker(30 * time.Second)
		refresh := time.NewTicker(p.refreshInt)
		defer probe.Stop()
		defer refresh.Stop()
		for {
			select {
			case <-p.checkStop:
				return
			case <-probe.C:
				p.probeAll()
			case <-refresh.C:
				p.refreshAddrs()
			}
		}
	}()
}

func (p *Pool) probeAll() {
	for _, u := range p.upstreams {
		if u.healthy.Load() && u.fails.Load() == 0 {
			continue // fast path: don't churn healthy upstreams
		}
		go func(u *upstream) {
			ctx, cancel := context.WithTimeout(context.Background(), p.timeout)
			defer cancel()
			m := new(mdns.Msg)
			m.SetQuestion(".", mdns.TypeNS)
			m.RecursionDesired = true
			if _, err := p.exchange(ctx, u, m); err == nil {
				u.healthy.Store(true)
			}
		}(u)
	}
}

func (p *Pool) refreshAddrs() {
	for _, u := range p.upstreams {
		if isIP(u.host) {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		ips, err := p.resolveBootstrap(ctx, u.host)
		cancel()
		if err == nil && len(ips) > 0 {
			a := net.JoinHostPort(ips[0].String(), u.port)
			u.addrCache.Store(&a)
		}
	}
}

// Close stops background loops.
func (p *Pool) Close() {
	close(p.checkStop)
	p.stopped.Wait()
}

// browserDoH performs a DoH query through the browser-fingerprint pool.
func (p *Pool) browserDoH(ctx context.Context, u *upstream, wire []byte) (*mdns.Msg, error) {
	if p.browserPool == nil || wire == nil {
		return nil, errNoUpstream
	}
	target := "https://" + u.host + ":" + u.port + u.path
	body, err := p.browserPool.Post(ctx, target, wire)
	if err != nil {
		return nil, err
	}
	out := new(mdns.Msg)
	if err := out.Unpack(body); err != nil {
		return nil, err
	}
	return out, nil
}

// idnaFqdn normalizes a query name for upstreams (ASCII + trailing dot).
func idnaFqdn(name string) string {
	d := strings.TrimSuffix(name, ".")
	if isASCII(d) {
		return strings.ToLower(d) + "."
	}
	if ascii, err := idnaProfile.ToASCII(d); err == nil {
		return ascii + "."
	}
	return name
}

// isASCII reports whether s is pure ASCII.
func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

var idnaProfile = idna.New(idna.MapForLookup(), idna.BidiRule())
