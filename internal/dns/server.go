// Package dns — server: listeners (UDP/TCP :53, DoT :853, DoH :443),
// pipeline (block → cache → upstream → uncloak), per-device identities.
package dns

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	mdns "github.com/miekg/dns"

	"github.com/0xsaurabhx/Supp/internal/store"
)

// Blocker is the subset of filter.Engine the pipeline needs.
type Blocker interface {
	Check(domain string) bool
	BlockIPv4() netip.Addr
	BlockIPv6() netip.Addr
}

// Server owns listeners and the request pipeline.
type Server struct {
	cfg    Config
	pool   *Pool
	filter Blocker
	cache  *replyCache
	log    *slog.Logger
	udp    []*mdns.Server
	tcp    []*mdns.Server
	dot    []*mdns.Server
	mux    *mdns.ServeMux
	http   *http.Server

	mu         sync.Mutex
	clientByID map[int64]string

	QueriesTotal atomic.Uint64
	BlockedTotal atomic.Uint64
	Live         *Metrics
	store        *store.Store
	browserPool  *BrowserPool
	perDeviceDoH bool
	domain       string
	shutdown     chan struct{}
	started      time.Time
	upstreams    []string
}

// Config carries resolved runtime settings for the DNS server.
type Config struct {
	ListenPlain  string // "0.0.0.0:53" or "" to disable
	ListenDoT    string // "0.0.0.0:853" or ""
	ListenDoH    string // "0.0.0.0:443" or ""
	DotCert      *tls.Certificate
	DoHCert      *tls.Certificate
	Domain       string // public name for per-device DoH paths
	PerDeviceDoH bool   // enable /dns/<token> paths
	Upstreams    []string
	Weights      []int
	Bootstrap    []string
	Timeout      time.Duration
	CacheSize    int
	CacheMinTTL  time.Duration
	CacheMaxTTL  time.Duration
	FailTTL      time.Duration
	Blocker      Blocker
	Store        *store.Store
	Browser      *BrowserPool
}

// NewServer builds the server (listeners start on Run).
func NewServer(cfg Config, log *slog.Logger) (*Server, error) {
	if cfg.Store == nil {
		return nil, errors.New("dns: store is required")
	}
	if cfg.Blocker == nil {
		return nil, errors.New("dns: blocker is required")
	}
	if cfg.CacheSize <= 0 {
		cfg.CacheSize = 65536
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 3 * time.Second
	}
	s := &Server{
		cfg:          cfg,
		log:          log,
		cache:        newReplyCache(cfg.CacheSize, 1*time.Hour),
		clientByID:   map[int64]string{},
		Live:         NewMetrics(),
		filter:       cfg.Blocker,
		store:        cfg.Store,
		browserPool:  cfg.Browser,
		perDeviceDoH: cfg.PerDeviceDoH,
		domain:       cfg.Domain,
		shutdown:     make(chan struct{}),
		started:      time.Now(),
		upstreams:    cfg.Upstreams,
	}
	var opts []PoolOption
	if cfg.Browser != nil {
		opts = append(opts, WithBrowserUpstream(cfg.Browser))
	}
	pool, err := NewPool(cfg.Upstreams, cfg.Weights, cfg.Bootstrap, cfg.Timeout, opts...)
	if err != nil {
		return nil, err
	}
	s.pool = pool
	pool.Start()
	return s, nil
}

// Run starts all listeners and blocks until ctx is cancelled.
func (s *Server) Run(ctx context.Context) error {
	// Plain DNS on UDP + TCP. Bind synchronously (errors surface here),
	// then serve in the background — miekg's ActivateAndServe blocks.
	if s.cfg.ListenPlain != "" {
		pc, err := net.ListenPacket("udp", s.cfg.ListenPlain)
		if err != nil {
			return fmt.Errorf("plain udp %s: %w", s.cfg.ListenPlain, err)
		}
		usrv := &mdns.Server{PacketConn: pc, Handler: s, UDPSize: 4096}
		s.udp = append(s.udp, usrv)
		go func() { _ = usrv.ActivateAndServe() }()

		ln, err := net.Listen("tcp", s.cfg.ListenPlain)
		if err != nil {
			return fmt.Errorf("plain tcp %s: %w", s.cfg.ListenPlain, err)
		}
		tsrv := &mdns.Server{Listener: ln, Handler: s}
		s.tcp = append(s.tcp, tsrv)
		go func() { _ = tsrv.ActivateAndServe() }()
		s.log.Info("plain dns listening", "addr", s.cfg.ListenPlain)
	}
	// DoT.
	if s.cfg.ListenDoT != "" && s.cfg.DotCert != nil {
		tlscfg := &tls.Config{
			Certificates: []tls.Certificate{*s.cfg.DotCert},
			MinVersion:   tls.VersionTLS12,
			NextProtos:   []string{"dot"},
		}
		ln, err := tls.Listen("tcp", s.cfg.ListenDoT, tlscfg)
		if err != nil {
			return fmt.Errorf("dot %s: %w", s.cfg.ListenDoT, err)
		}
		srv := &mdns.Server{Listener: ln, Handler: s}
		s.dot = append(s.dot, srv)
		go func() { _ = srv.ActivateAndServe() }()
		s.log.Info("dot listening", "addr", s.cfg.ListenDoT)
	}
	// DoH via net/http.
	if s.cfg.ListenDoH != "" && s.cfg.DoHCert != nil {
		mux := http.NewServeMux()
		mux.HandleFunc("/dns-query", s.handleDoH)
		if s.perDeviceDoH {
			mux.HandleFunc("/dns/", s.handleDoH)
		}
		s.http = &http.Server{
			Addr:    s.cfg.ListenDoH,
			Handler: mux,
			TLSConfig: &tls.Config{
				Certificates: []tls.Certificate{*s.cfg.DoHCert},
				MinVersion:   tls.VersionTLS12,
			},
			ReadHeaderTimeout: 10 * time.Second,
		}
		ln, err := tls.Listen("tcp", s.cfg.ListenDoH, s.http.TLSConfig)
		if err != nil {
			return fmt.Errorf("doh %s: %w", s.cfg.ListenDoH, err)
		}
		go func() {
			<-ctx.Done()
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = s.http.Shutdown(shutdownCtx)
		}()
		go func() {
			if err := s.http.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
				s.log.Error("doh serve", "err", err)
			}
		}()
		s.log.Info("doh listening", "addr", s.cfg.ListenDoH)
	}

	<-ctx.Done()
	s.Close()
	return nil
}

// Close stops all listeners and the upstream pool.
func (s *Server) Close() {
	for _, srv := range append(s.udp, s.tcp...) {
		_ = srv.Shutdown()
	}
	for _, srv := range s.dot {
		_ = srv.Shutdown()
	}
	if s.http != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		_ = s.http.Shutdown(ctx)
		cancel()
	}
	s.pool.Close()
	close(s.shutdown)
}

// ServeDNS is the miekg/dns handler for plain DNS and DoT.
func (s *Server) ServeDNS(w mdns.ResponseWriter, r *mdns.Msg) {
	clientID, clientName := int64(0), "local"
	start := time.Now()
	resp, blocked, cached := s.handle(r, clientID, clientName)
	if resp == nil {
		mdns.HandleFailed(w, r)
		s.observe(clientName, clientID, r, false, false, start)
		return
	}
	w.WriteMsg(resp)
	s.observe(clientName, clientID, r, blocked, cached, start)
}

func (s *Server) observe(clientName string, clientID int64, r *mdns.Msg, blocked, cached bool, start time.Time) {
	qtype := ""
	if len(r.Question) > 0 {
		qtype = mdns.Type(r.Question[0].Qtype).String()
	}
	qname := ""
	if len(r.Question) > 0 {
		qname = strings.TrimSuffix(strings.ToLower(r.Question[0].Name), ".")
	}
	s.Live.Observe(clientName, clientID, qname, qtype, blocked, cached)
	if s.store != nil {
		s.store.RecordQuery(clientID, qname, qtype, blocked, 0)
	}
}

// handle processes a query: block → cache → upstream → uncloak.
func (s *Server) handle(r *mdns.Msg, clientID int64, clientName string) (*mdns.Msg, bool, bool) {
	if len(r.Question) == 0 {
		return nil, false, false
	}
	q := r.Question[0]
	qname := strings.ToLower(strings.TrimSuffix(q.Name, "."))

	// Blocking first: block even before touching the cache.
	blocked := s.filter.Check(qname)
	if blocked {
		resp := s.blockResponse(r)
		return resp, true, false
	}

	// Cache lookup; stale answers are only used if upstreams all fail.
	if m, fresh, ok := s.cache.get(r); ok {
		if fresh {
			m.Id = r.Id
			return m, false, true
		}
		// serve-stale path: try upstreams; fall back to stale below
		if resp, err := s.resolve(r, clientID, qname); err == nil && resp != nil {
			return resp, false, false
		}
		m.Id = r.Id
		s.Live.ObserveStale()
		return m, false, true
	}

	resp, err := s.resolve(r, clientID, qname)
	if err != nil {
		s.log.Debug("upstream failed", "qname", qname, "err", err)
		return nil, false, false
	}
	return resp, false, false
}

// resolve sends the query upstream and post-processes the reply.
func (s *Server) resolve(r *mdns.Msg, clientID int64, qname string) (*mdns.Msg, error) {
	req := r.Copy()
	req.Id = 0
	if len(req.Question) > 0 {
		req.Question[0].Name = idnaFqdn(qname)
	}
	// Strip client EDNS0; re-add minimal options on the reply as needed.
	req.Extra = nil
	resp, err := s.pool.Query(context.Background(), req)
	if err != nil {
		return nil, err
	}
	resp.Id = r.Id
	resp.Question = r.Question

	// CNAME uncloaking: re-check each name in the answer chain.
	s.uncloak(qname, resp)

	// Cache only legitimate replies.
	if resp.Rcode == mdns.RcodeSuccess || resp.Rcode == mdns.RcodeNameError {
		ttl := clampTTLs(resp, s.cfg.CacheMinTTL, s.cfg.CacheMaxTTL)
		if resp.Rcode == mdns.RcodeNameError && s.cfg.FailTTL > 0 {
			ttl = s.cfg.FailTTL
		}
		s.cache.put(r, resp, ttl)
	}
	return resp, nil
}

// uncloak walks A/AAAA/CNAME chains: if any alias target is a tracker,
// swap the whole answer for a block response (keeps clients consistent).
func (s *Server) uncloak(qname string, resp *mdns.Msg) {
	if resp.Rcode != mdns.RcodeSuccess || len(resp.Answer) == 0 {
		return
	}
	seen := map[string]bool{qname: true}
	var blockedName string
	for _, rr := range resp.Answer {
		var target string
		switch v := rr.(type) {
		case *mdns.CNAME:
			target = strings.ToLower(strings.TrimSuffix(v.Target, "."))
		case *mdns.A:
			// A records for the original name are fine; cloaked trackers
			// normally appear as CNAME chains, handled above.
		case *mdns.AAAA:
		}
		if target != "" && !seen[target] {
			seen[target] = true
			if s.filter.Check(target) {
				blockedName = target
				break
			}
		}
	}
	if blockedName != "" {
		// NOERROR with an empty answer: clients fail fast and do not fall
		// back to other resolvers (as they would on SERVFAIL).
		resp.Answer = nil
		resp.Ns = nil
		resp.Extra = nil
	}
}

// blockResponse builds the synthetic reply for blocked names.
func (s *Server) blockResponse(r *mdns.Msg) *mdns.Msg {
	resp := new(mdns.Msg)
	resp.SetReply(r)
	resp.RecursionAvailable = true
	resp.Rcode = mdns.RcodeSuccess
	q := r.Question[0]
	switch q.Qtype {
	case mdns.TypeA:
		a4 := s.filter.BlockIPv4().As4()
		resp.Answer = []mdns.RR{&mdns.A{
			Hdr: mdns.RR_Header{Name: q.Name, Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 60},
			A:   net.IPv4(a4[0], a4[1], a4[2], a4[3]).To4(),
		}}
	case mdns.TypeAAAA:
		a6 := s.filter.BlockIPv6().As16()
		resp.Answer = []mdns.RR{&mdns.AAAA{
			Hdr:  mdns.RR_Header{Name: q.Name, Rrtype: mdns.TypeAAAA, Class: mdns.ClassINET, Ttl: 60},
			AAAA: net.IP(a6[:]).To16(),
		}}
	default:
		resp.Rcode = mdns.RcodeNameError
	}
	return resp
}

// handleDoH serves RFC 8484 GET/POST, including per-device paths.
func (s *Server) handleDoH(w http.ResponseWriter, req *http.Request) {
	clientID, clientName := int64(0), "doh"
	if s.perDeviceDoH && strings.HasPrefix(req.URL.Path, "/dns/") {
		tok := strings.TrimPrefix(req.URL.Path, "/dns/")
		tok = strings.TrimSuffix(tok, "/")
		if tok == "" || len(tok) < 16 {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		c, err := s.store.ClientByToken(tok)
		if err != nil || !c.Active {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		clientID, clientName = c.ID, c.Name
		_ = s.store.TouchClient(c.ID, tok)
	}
	var wire []byte
	var err error
	switch req.Method {
	case http.MethodGet:
		par := req.URL.Query().Get("dns")
		if par == "" {
			http.Error(w, "missing dns param", http.StatusBadRequest)
			return
		}
		wire, err = base64RawURLDecode(par)
		if err != nil {
			http.Error(w, "bad dns param", http.StatusBadRequest)
			return
		}
	case http.MethodPost:
		if req.Header.Get("Content-Type") != "application/dns-message" {
			http.Error(w, "bad content type", http.StatusUnsupportedMediaType)
			return
		}
		wire, err = io.ReadAll(io.LimitReader(req.Body, 64<<10))
		if err != nil {
			http.Error(w, "read error", http.StatusBadRequest)
			return
		}
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	q := new(mdns.Msg)
	if err := q.Unpack(wire); err != nil {
		http.Error(w, "bad dns message", http.StatusBadRequest)
		return
	}
	start := time.Now()
	resp, blocked, cached := s.handle(q, clientID, clientName)
	if resp == nil {
		http.Error(w, "resolution failed", http.StatusServiceUnavailable)
		s.observe(clientName, clientID, q, false, false, start)
		return
	}
	out, err := resp.Pack()
	if err != nil {
		http.Error(w, "pack error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/dns-message")
	w.Header().Set("Cache-Control", fmt.Sprintf("max-age=%d", ttlOf(resp)))
	_, _ = w.Write(out)
	s.observe(clientName, clientID, q, blocked, cached, start)
}

func ttlOf(m *mdns.Msg) uint32 {
	for _, rr := range m.Answer {
		return rr.Header().Ttl
	}
	return 60
}

// base64RawURLDecode decodes unpadded base64url (RFC 8484 GET encoding).
func base64RawURLDecode(s string) ([]byte, error) {
	return base64RawURLCodec.DecodeString(s)
}

var base64RawURLCodec = base64.RawURLEncoding.Strict()

// ClientName resolves an ID to a friendly name for the dashboard.
func (s *Server) ClientName(id int64) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if n, ok := s.clientByID[id]; ok {
		return n
	}
	return fmt.Sprintf("device-%d", id)
}
