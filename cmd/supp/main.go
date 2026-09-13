// Command supp runs the Supp privacy DNS server and its management CLI.
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/0xsaurabhx/Supp/internal/admin"
	"github.com/0xsaurabhx/Supp/internal/config"
	"github.com/0xsaurabhx/Supp/internal/dns"
	"github.com/0xsaurabhx/Supp/internal/filter"
	"github.com/0xsaurabhx/Supp/internal/ops"
	"github.com/0xsaurabhx/Supp/internal/store"
)

var version = "dev"
var commit = "none"

func main() {
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "init":
		err = cmdInit(os.Args[2:], log)
	case "server":
		err = cmdServer(os.Args[2:], log)
	case "client":
		err = cmdClient(os.Args[2:], log)
	case "status":
		err = cmdStatus(os.Args[2:], log)
	case "doctor":
		err = cmdDoctor(os.Args[2:], log)
	case "version", "--version", "-v":
		fmt.Printf("supp %s (%s)\n", version, commit)
	case "help", "--help", "-h":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
	if err != nil {
		log.Error("supp", "err", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Print(`Supp — self-hosted privacy DNS (DoH/DoT/plain) with ad & tracker blocking

Usage:
  supp init [--config PATH] [--domain DNSNAME] [--token TOK]
  supp server [--config PATH]
  supp client add <name> | list | revoke <name> [--config PATH]
  supp status [--config PATH]
  supp doctor [--config PATH]
  supp version
`)
}

func configPath(args []string) string {
	// Manual scan: flag.Parse stops at the first non-flag argument, but
	// --config may appear after a subcommand (supp client list --config X).
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "--config" || args[i] == "-config":
			if i+1 < len(args) {
				return args[i+1]
			}
		case strings.HasPrefix(args[i], "--config="), strings.HasPrefix(args[i], "-config="):
			return strings.TrimPrefix(strings.TrimPrefix(args[i], "--"), "-")[len("config="):]
		}
	}
	if v := os.Getenv("SUPP_CONFIG"); v != "" {
		return v
	}
	for _, c := range []string{"/etc/supp/config.toml", "supp.toml"} {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	return "/etc/supp/config.toml"
}

func cmdInit(args []string, log *slog.Logger) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	domain := fs.String("domain", "", "public DNS name of this server")
	token := fs.String("token", "", "admin token (generated when empty)")
	cfgPath := configPath(args)
	if err := fs.Parse(stripConfigArg(args)); err != nil {
		return err
	}
	return ops.Run(ops.Options{ConfigPath: cfgPath, Domain: *domain, AdminToken: *token})
}

// stripConfigArg removes --config from args before per-command flag parsing.
func stripConfigArg(args []string) []string {
	out := args[:0:0]
	for i := 0; i < len(args); i++ {
		if args[i] == "--config" || args[i] == "-config" {
			i++
			continue
		}
		if strings.HasPrefix(args[i], "--config=") || strings.HasPrefix(args[i], "-config=") {
			continue
		}
		out = append(out, args[i])
	}
	return out
}

func cmdServer(args []string, log *slog.Logger) error {
	cfgPath := configPath(args)
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	return runServer(cfg, log)
}

func runServer(cfg *config.Config, log *slog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := os.MkdirAll(cfg.Server.DataDir, 0o750); err != nil {
		return err
	}

	// Storage.
	st, err := store.Open(filepath.Join(cfg.Server.DataDir, "supp.db"), cfg.Log.Queries, cfg.Log.Retention.D())
	if err != nil {
		return fmt.Errorf("store: %w", err)
	}
	defer st.Close()
	go st.Loop(ctx.Done())

	// Filter engine.
	specs := make([]filter.ListSpec, 0, len(cfg.Block.Lists))
	for _, l := range cfg.Block.Lists {
		specs = append(specs, filter.ListSpec{Name: l.Name, URL: l.URL, Format: l.Format})
	}
	eng := filter.NewEngine(cfg.Server.DataDir, specs, cfg.Block.Allowlist, cfg.Block.Denylist, cfg.Block.Refresh.D())
	eng.SetResponseIP(cfg.Block.ResponseIP, "::")
	if cfg.Block.Enabled {
		log.Info("loading blocklists", "lists", len(specs))
		rctx, cancel := context.WithTimeout(ctx, 90*time.Second)
		if err := eng.Refresh(rctx); err != nil {
			log.Warn("blocklist refresh incomplete", "err", err)
		}
		cancel()
		go eng.Loop(ctx)
	} else {
		log.Info("blocking disabled by config")
	}

	// Browser-fingerprint fallback upstream: created up front but kept cold;
	// it is only dialed when every configured upstream is failing.
	var browser *dns.BrowserPool
	if bp, err := dns.NewBrowserPool(2); err != nil {
		log.Warn("browser-fingerprint upstream unavailable", "err", err)
	} else {
		browser = bp
		defer bp.Close()
	}

	// TLS (only needed for encrypted listeners).
	var certs *ops.TLSCerts
	needTLS := cfg.DNS.Listen.DoT != "" || cfg.DNS.Listen.DoH != ""
	if needTLS {
		certs, err = ops.GetCerts(cfg, log)
		if err != nil {
			return err
		}
	}

	var tlsFunc func(nextProtos ...string) *tls.Config
	if certs != nil {
		tlsFunc = certs.TLSConfig
	}

	// DNS server.
	srv, err := dns.NewServer(dns.Config{
		ListenPlain:   cfg.DNS.Listen.Plain,
		ListenDoT:     cfg.DNS.Listen.DoT,
		ListenDoH:     cfg.DNS.Listen.DoH,
		DotCert:       certPtr(certs),
		DoHCert:       certPtr(certs),
		TLSConfigFunc: tlsFunc,
		Domain:        cfg.Server.Domain,
		PerDeviceDoH: true, // token-gated paths; work with or without a domain
		Upstreams:    upstreamURLs(cfg),
		Weights:      upstreamWeights(cfg),
		Bootstrap:    cfg.DNS.Bootstrap,
		Timeout:      cfg.DNS.Timeout.D(),
		CacheSize:    cfg.DNS.Cache.Size,
		CacheMinTTL:  cfg.DNS.Cache.MinTTL.D(),
		CacheMaxTTL:  cfg.DNS.Cache.MaxTTL.D(),
		FailTTL:      cfg.DNS.Cache.FailTTL.D(),
		Blocker:      eng,
		Store:        st,
		Browser:      browser,
	}, log)
	if err != nil {
		return err
	}

	// Admin dashboard (failure here must not kill DNS).
	if cfg.Admin.Enabled {
		go func() {
			adminSrv := admin.New(admin.Deps{
				Store:   st,
				Filter:  eng,
				Live:    srv.Live,
				Version: version,
				Token:   cfg.Admin.Token,
				Log:     log,
			})
			errCh := make(chan error, 1)
			go adminSrv.Run(cfg.Admin.Listen, errCh)
			if err := <-errCh; err != nil {
				log.Warn("admin dashboard disabled", "err", err)
			}
			<-ctx.Done()
			adminSrv.Close()
		}()
	}

	log.Info("supp starting", "version", version, "domain", cfg.Server.Domain)
	return srv.Run(ctx)
}

func certPtr(c *ops.TLSCerts) *tls.Certificate {
	if c == nil {
		return nil
	}
	return c.Cert
}

func upstreamURLs(cfg *config.Config) []string {
	out := make([]string, 0, len(cfg.DNS.Upstreams))
	for _, u := range cfg.DNS.Upstreams {
		out = append(out, u.URL)
	}
	return out
}

func upstreamWeights(cfg *config.Config) []int {
	out := make([]int, 0, len(cfg.DNS.Upstreams))
	for _, u := range cfg.DNS.Upstreams {
		out = append(out, u.Weight)
	}
	return out
}

func cmdClient(args []string, log *slog.Logger) error {
	if len(args) < 1 {
		return errors.New("usage: supp client add <name> | list | revoke <name>")
	}
	cfg, err := config.Load(configPath(args))
	if err != nil {
		return err
	}
	st, err := store.Open(filepath.Join(cfg.Server.DataDir, "supp.db"), false, cfg.Log.Retention.D())
	if err != nil {
		return err
	}
	defer st.Close()

	sub := args[0]
	rest := args[1:]
	switch sub {
	case "add":
		if len(rest) < 1 {
			return errors.New("usage: supp client add <name>")
		}
		c, err := st.CreateClient(rest[0])
		if err != nil {
			return err
		}
		fmt.Println("device created:")
		fmt.Println("  name:      ", c.Name)
		if cfg.Server.Domain != "" {
			fmt.Printf("  DoH URL:    https://%s/dns/%s\n", cfg.Server.Domain, c.Token)
			fmt.Printf("  DoT:        %s (plain, IP-attributed)\n", cfg.Server.Domain)
		} else {
			fmt.Printf("  token:      %s\n", c.Token)
			fmt.Println("  (set server.domain in config to get ready-made URLs)")
		}
		fmt.Println("  keep the token secret: it identifies this device")
	case "list":
		cs, err := st.ListClients()
		if err != nil {
			return err
		}
		rows, _ := st.PerClient(time.Now().Add(-24 * time.Hour))
		byID := map[int64]store.ClientRow{}
		for _, r := range rows {
			byID[r.ID] = r
		}
		if len(cs) == 0 {
			fmt.Println("no devices")
			return nil
		}
		for _, c := range cs {
			status := "active"
			if !c.Active {
				status = "REVOKED"
			}
			fmt.Printf("%-20s %-8s queries24h=%-6d blocked24h=%-5d last=%s\n",
				c.Name, status, byID[c.ID].Queries, byID[c.ID].Blocked, c.LastSeen.Format("2006-01-02 15:04"))
		}
	case "revoke", "remove", "delete":
		if len(rest) < 1 {
			return errors.New("usage: supp client revoke <name>")
		}
		c, err := st.ClientByName(rest[0])
		if err != nil {
			return fmt.Errorf("find client: %w", err)
		}
		if err := st.DeleteClient(c.ID); err != nil {
			return err
		}
		fmt.Printf("removed %s\n", c.Name)
	default:
		return fmt.Errorf("unknown client subcommand %q", sub)
	}
	return nil
}

func cmdStatus(args []string, log *slog.Logger) error {
	cfg, err := config.Load(configPath(args))
	if err != nil {
		return err
	}
	req, _ := http.NewRequest(http.MethodGet, "http://"+cfg.Admin.Listen+"/api/stats", nil)
	req.Header.Set("X-Admin-Token", cfg.Admin.Token)
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("admin API unreachable (is supp server running?): %w", err)
	}
	defer resp.Body.Close()
	var pretty map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&pretty); err != nil {
		return err
	}
	out, _ := json.MarshalIndent(pretty, "", "  ")
	fmt.Println(string(out))
	return nil
}

func cmdDoctor(args []string, log *slog.Logger) error {
	cfg, err := config.Load(configPath(args))
	if err != nil {
		return err
	}
	ok := true
	check := func(name string, err error) {
		if err != nil {
			ok = false
			fmt.Printf("✖ %s: %v\n", name, err)
			return
		}
		fmt.Printf("✔ %s\n", name)
	}
	check("config valid", nil)
	check("data dir writable", writableDir(cfg.Server.DataDir))

	// If this instance is already serving, port-bind checks are noise.
	if serverAlive(cfg) {
		fmt.Println("✔ supp server already running (skipping port-bind checks)")
	} else {
		for _, p := range []struct{ name, addr string }{
			{"plain dns port bindable", cfg.DNS.Listen.Plain},
			{"dot port bindable", cfg.DNS.Listen.DoT},
			{"doh port bindable", cfg.DNS.Listen.DoH},
		} {
			if p.addr == "" {
				continue
			}
			check(p.name, portFree(p.addr))
		}
	}
	if cfg.Server.Domain != "" {
		_, err := net.LookupHost(cfg.Server.Domain)
		check("domain resolves ("+cfg.Server.Domain+")", err)
	}
	for _, u := range cfg.DNS.Upstreams {
		host := hostOf(u.URL)
		_, err := net.LookupHost(host)
		check("upstream reachable ("+host+")", err)
	}
	if !ok {
		return errors.New("doctor found problems")
	}
	fmt.Println("all checks passed")
	return nil
}

// serverAlive probes the admin API of a running instance.
func serverAlive(cfg *config.Config) bool {
	req, _ := http.NewRequest(http.MethodGet, "http://"+cfg.Admin.Listen+"/api/stats", nil)
	req.Header.Set("X-Admin-Token", cfg.Admin.Token)
	client := &http.Client{Timeout: time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

func writableDir(dir string) error {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	probe := filepath.Join(dir, ".probe")
	if err := os.WriteFile(probe, []byte("x"), 0o600); err != nil {
		return err
	}
	return os.Remove(probe)
}

func portFree(addr string) error {
	// A listener already bound by us (systemd restart) counts as busy-but-ok
	// only for TCP; for a pre-flight check we require it to be bindable.
	tcp, err := net.Listen("tcp", addr)
	if err == nil {
		tcp.Close()
		return nil
	}
	udp, uerr := net.ListenPacket("udp", addr)
	if uerr == nil {
		udp.Close()
		return nil
	}
	return fmt.Errorf("%s busy (tcp: %v)", addr, err)
}

func hostOf(url string) string {
	s := url
	for _, p := range []string{"doh://", "dot://", "tls://", "udp://", "tcp://", "https://"} {
		s = strings.TrimPrefix(s, p)
	}
	if i := strings.IndexByte(s, '/'); i >= 0 {
		s = s[:i]
	}
	if i := strings.LastIndexByte(s, ':'); i >= 0 {
		s = s[:i]
	}
	return s
}
