// Package admin serves the local dashboard and management API.
package admin

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"runtime"
	"strconv"
	"sync"
	"time"

	"github.com/0xsaurabhx/Supp/internal/dns"
	"github.com/0xsaurabhx/Supp/internal/filter"
	"github.com/0xsaurabhx/Supp/internal/store"
	"github.com/0xsaurabhx/Supp/internal/wg"
)

// Deps wires the admin server into running components.
type Deps struct {
	Store   *store.Store
	Filter  *filter.Engine
	Live    *dns.Metrics
	WG      *wg.Service // nil when the VPN module is disabled
	Version string
	Token   string
	Log     *slog.Logger
}

// Server is the admin HTTP server.
type Server struct {
	deps   Deps
	mux    *http.ServeMux
	srv    *http.Server
	mu     sync.Mutex
	visits int
}

// New builds the admin server (call Run to start).
func New(d Deps) *Server {
	s := &Server{deps: d}
	m := http.NewServeMux()
	m.HandleFunc("GET /{$}", s.pageOverview)
	m.HandleFunc("GET /live", s.pageLive)
	m.HandleFunc("GET /clients", s.pageClients)
	m.HandleFunc("GET /blocklists", s.pageBlocklists)
	m.HandleFunc("GET /setup", s.pageSetup)
	m.HandleFunc("GET /wg", s.pageWG)
	m.HandleFunc("GET /api/wg/status", s.apiWGStatus)
	m.HandleFunc("POST /api/wg/peers", s.apiWGPeerCreate)
	m.HandleFunc("DELETE /api/wg/peers/{id}", s.apiWGPeerDelete)
	m.HandleFunc("PATCH /api/wg/peers/{id}", s.apiWGPeerToggle)
	m.HandleFunc("GET /api/wg/peers/{id}/conf", s.apiWGPeerConf)
	m.HandleFunc("GET /api/wg/peers/{id}/qr.png", s.apiWGPeerQR)
	m.HandleFunc("GET /api/stats", s.apiStats)
	m.HandleFunc("GET /api/clients", s.apiClients)
	m.HandleFunc("POST /api/clients", s.apiClientCreate)
	m.HandleFunc("DELETE /api/clients/{id}", s.apiClientDelete)
	m.Handle("GET /static/", http.FileServer(http.FS(templateFS)))
	s.mux = m
	return s
}

// Run starts listening; blocks until ctx done or listen fails.
func (s *Server) Run(addr string, listenErr chan<- error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		listenErr <- err
		return
	}
	s.srv = &http.Server{
		Handler:           s.auth(s.mux),
		ReadHeaderTimeout: 5 * time.Second,
	}
	s.deps.Log.Info("admin dashboard listening", "addr", addr)
	listenErr <- nil
	if err := s.srv.Serve(ln); err != nil && err != http.ErrServerClosed {
		s.deps.Log.Error("admin serve", "err", err)
	}
}

// Close shuts down the admin server.
func (s *Server) Close() {
	if s.srv != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = s.srv.Shutdown(ctx)
	}
}

// auth enforces the admin token on everything (constant-time compare).
func (s *Server) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok := r.Header.Get("X-Admin-Token")
		if tok == "" {
			if c, err := r.Cookie("supp_admin"); err == nil {
				tok = c.Value
			}
		}
		if tok == "" {
			tok = r.URL.Query().Get("token")
		}
		if s.deps.Token == "" || subtle.ConstantTimeCompare([]byte(tok), []byte(s.deps.Token)) != 1 {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(loginPageHTML))
			return
		}
		// Set a cookie so browser navigation keeps working.
		if r.URL.Query().Get("token") != "" {
			http.SetCookie(w, &http.Cookie{Name: "supp_admin", Value: tok, Path: "/", HttpOnly: true, MaxAge: 43200})
			clean := r.URL
			q := clean.Query()
			q.Del("token")
			clean.RawQuery = q.Encode()
			http.Redirect(w, r, clean.String(), http.StatusFound)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) apiStats(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.stats(r))
}

type statsView struct {
	Version        string                `json:"version"`
	Uptime         string                `json:"uptime"`
	QueriesTotal   uint64                `json:"queries_total"`
	BlockedTotal   uint64                `json:"blocked_total"`
	CachedTotal    uint64                `json:"cached_total"`
	BlockPercent   float64               `json:"block_percent"`
	BlockedDomains int                   `json:"blocked_domains"`
	TopBlocked     []store.DomainRow     `json:"top_blocked"`
	Clients        []store.ClientRow     `json:"clients"`
	MemAllocMB     float64               `json:"mem_alloc_mb"`
	NumGoroutine   int                   `json:"goroutines"`
	Sources        []filter.SourceStatus `json:"sources"`
	Recent         []dns.RecentQuery     `json:"recent"`
}

func (s *Server) stats(r *http.Request) statsView {
	since := time.Now().Add(-24 * time.Hour)
	snap := s.deps.Live.Snapshot()
	var v statsView
	v.Version = s.deps.Version
	v.Uptime = snap.Uptime.Round(time.Second).String()
	v.QueriesTotal = snap.QueriesTotal
	v.BlockedTotal = snap.BlockedTotal
	v.CachedTotal = snap.CachedTotal
	if v.QueriesTotal > 0 {
		v.BlockPercent = float64(v.BlockedTotal) / float64(v.QueriesTotal) * 100
	}
	if s.deps.Filter != nil {
		fst := s.deps.Filter.Stats()
		v.BlockedDomains = fst.BlockedDomains
		v.Sources = fst.Sources
	}
	if s.deps.Store != nil {
		v.TopBlocked, _ = s.deps.Store.TopDomains(since, 50, true)
		v.Clients, _ = s.deps.Store.PerClient(since)
		qStore, bStore := s.deps.Store.Totals(time.Time{})
		if qStore > v.QueriesTotal {
			v.QueriesTotal = qStore
		}
		if bStore > v.BlockedTotal {
			v.BlockedTotal = bStore
		}
		if dbLogs, err := s.deps.Store.RecentLog(100); err == nil && len(dbLogs) > 0 {
			v.Recent = make([]dns.RecentQuery, 0, len(dbLogs))
			for _, r := range dbLogs {
				clientName := r.ClientName
				if clientName == "" {
					clientName = "Default Client"
				}
				v.Recent = append(v.Recent, dns.RecentQuery{
					TS:      time.Unix(r.TS, 0),
					Client:  clientName,
					QName:   r.QName,
					QType:   r.QType,
					Blocked: r.Blocked == 1,
					Cached:  false,
				})
			}
		}
	}
	if len(v.Recent) == 0 {
		v.Recent = snap.Recent
	}
	if v.QueriesTotal > 0 {
		v.BlockPercent = float64(v.BlockedTotal) / float64(v.QueriesTotal) * 100
	}
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	v.MemAllocMB = float64(m.Alloc) / (1 << 20)
	v.NumGoroutine = runtime.NumGoroutine()
	return v
}

func (s *Server) apiClients(w http.ResponseWriter, r *http.Request) {
	cs, err := s.deps.Store.ListClients()
	if err != nil {
		httpError(w, 500, err.Error())
		return
	}
	writeJSON(w, cs)
}

func (s *Server) apiClientCreate(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&in); err != nil || in.Name == "" {
		httpError(w, 400, "name required")
		return
	}
	c, err := s.deps.Store.CreateClient(in.Name)
	if err != nil {
		httpError(w, 500, err.Error())
		return
	}
	writeJSON(w, c)
}

func (s *Server) apiClientDelete(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		httpError(w, 400, "bad id")
		return
	}
	if err := s.deps.Store.DeleteClient(id); err != nil {
		httpError(w, 500, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) pageOverview(w http.ResponseWriter, r *http.Request) {
	v := s.stats(r)
	s.mu.Lock()
	s.visits++
	s.mu.Unlock()
	render(w, pageData{View: "overview", Stats: &v, Token: s.deps.Token})
}

// pageLive returns just the live-cards fragment for htmx polling.
func (s *Server) pageLive(w http.ResponseWriter, r *http.Request) {
	v := s.stats(r)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = tpl.ExecuteTemplate(w, "live", &v)
}

func (s *Server) pageClients(w http.ResponseWriter, r *http.Request) {
	v := s.stats(r)
	render(w, pageData{View: "clients", Stats: &v, Token: s.deps.Token})
}

func (s *Server) pageBlocklists(w http.ResponseWriter, r *http.Request) {
	v := s.stats(r)
	render(w, pageData{View: "blocklists", Stats: &v, Token: s.deps.Token})
}

func (s *Server) pageSetup(w http.ResponseWriter, r *http.Request) {
	v := s.stats(r)
	render(w, pageData{View: "setup", Stats: &v, Token: s.deps.Token})
}

func (s *Server) pageWG(w http.ResponseWriter, r *http.Request) {
	v := s.stats(r)
	if s.deps.WG != nil {
		st := s.deps.WG.Status()
		render(w, pageData{View: "wg", Stats: &v, Token: s.deps.Token, WG: &st})
		return
	}
	render(w, pageData{View: "wg", Stats: &v, Token: s.deps.Token})
}

// apiWGStatus returns the VPN status JSON (or 409 when WG is disabled).
func (s *Server) apiWGStatus(w http.ResponseWriter, r *http.Request) {
	if s.deps.WG == nil {
		httpError(w, 409, "wireguard module not enabled (run 'supp wg enable')")
		return
	}
	writeJSON(w, s.deps.WG.Status())
}

func (s *Server) apiWGPeerCreate(w http.ResponseWriter, r *http.Request) {
	if s.deps.WG == nil {
		httpError(w, 409, "wireguard module not enabled")
		return
	}
	var in struct {
		Name       string `json:"name"`
		Split      bool   `json:"split"`
		DeviceName string `json:"device"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&in); err != nil || in.Name == "" {
		httpError(w, 400, "name required")
		return
	}
	var clientID int64
	if in.DeviceName != "" {
		if c, err := s.deps.Store.ClientByName(in.DeviceName); err == nil {
			clientID = c.ID
		}
	}
	full := !in.Split
	p, err := s.deps.WG.AddPeer(in.Name, full, clientID)
	if err != nil {
		httpError(w, 500, err.Error())
		return
	}
	writeJSON(w, p)
}

func (s *Server) apiWGPeerDelete(w http.ResponseWriter, r *http.Request) {
	if s.deps.WG == nil {
		httpError(w, 409, "wireguard module not enabled")
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		httpError(w, 400, "bad id")
		return
	}
	if err := s.deps.WG.RemovePeer(id); err != nil {
		httpError(w, 500, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// apiWGPeerToggle revokes/restores a peer. Body {"active": bool}.
func (s *Server) apiWGPeerToggle(w http.ResponseWriter, r *http.Request) {
	if s.deps.WG == nil {
		httpError(w, 409, "wireguard module not enabled")
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		httpError(w, 400, "bad id")
		return
	}
	var in struct {
		Active *bool `json:"active"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1024)).Decode(&in); err != nil || in.Active == nil {
		httpError(w, 400, "active (bool) required")
		return
	}
	if err := s.deps.WG.SetPeerActive(id, *in.Active); err != nil {
		httpError(w, 500, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// apiWGPeerConf serves the peer's wg-quick config as a download.
func (s *Server) apiWGPeerConf(w http.ResponseWriter, r *http.Request) {
	if s.deps.WG == nil {
		httpError(w, 409, "wireguard module not enabled")
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		httpError(w, 400, "bad id")
		return
	}
	p, err := s.deps.Store.WgPeerByID(id)
	if err != nil {
		httpError(w, 404, "peer not found")
		return
	}
	conf, err := s.deps.WG.PeerConf(p)
	if err != nil {
		httpError(w, 500, err.Error())
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q.conf", p.Name))
	_, _ = w.Write([]byte(conf))
}

// apiWGPeerQR serves the peer config as a scannable PNG.
func (s *Server) apiWGPeerQR(w http.ResponseWriter, r *http.Request) {
	if s.deps.WG == nil {
		httpError(w, 409, "wireguard module not enabled")
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		httpError(w, 400, "bad id")
		return
	}
	p, err := s.deps.Store.WgPeerByID(id)
	if err != nil {
		httpError(w, 404, "peer not found")
		return
	}
	conf, err := s.deps.WG.PeerConf(p)
	if err != nil {
		httpError(w, 500, err.Error())
		return
	}
	png, err := wg.QRPNG(conf, 512)
	if err != nil {
		httpError(w, 500, err.Error())
		return
	}
	w.Header().Set("Content-Type", "image/png")
	_, _ = w.Write(png)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func httpError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
