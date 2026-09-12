// Package admin serves the local dashboard and management API.
package admin

import (
	"context"
	"crypto/subtle"
	"encoding/json"
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
)

// Deps wires the admin server into running components.
type Deps struct {
	Store   *store.Store
	Filter  *filter.Engine
	Live    *dns.Metrics
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
		v.TopBlocked, _ = s.deps.Store.TopDomains(since, 15, true)
		v.Clients, _ = s.deps.Store.PerClient(since)
	}
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	v.MemAllocMB = float64(m.Alloc) / (1 << 20)
	v.NumGoroutine = runtime.NumGoroutine()
	v.Recent = snap.Recent
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

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func httpError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
