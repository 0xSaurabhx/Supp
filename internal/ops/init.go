// Package ops implements VPS bootstrap: config generation, admin token,
// ACME setup and firewall installation (called by `supp init`).
package ops

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/0xsaurabhx/Supp/internal/config"
)

// Options for init.
type Options struct {
	ConfigPath string
	Domain     string
	AdminToken string // reuse an existing token when set
}

// Run generates or updates the config and prints next steps.
func Run(o Options) error {
	var cfg *config.Config
	if _, err := os.Stat(o.ConfigPath); err == nil {
		loaded, err := config.Load(o.ConfigPath)
		if err != nil {
			return fmt.Errorf("existing config invalid: %w", err)
		}
		cfg = loaded
	} else {
		cfg = config.Default()
	}
	changed := false

	if o.Domain != "" && cfg.Server.Domain != o.Domain {
		cfg.Server.Domain = o.Domain
		changed = true
	} else if o.Domain == "" && cfg.Server.Domain == "" {
		fmt.Print("Public DNS name for this server (e.g. dns.example.com, blank to skip): ")
		line := readLine()
		if line != "" {
			cfg.Server.Domain = line
			changed = true
		}
	}

	if cfg.Admin.Token == "" {
		tok := o.AdminToken
		if tok == "" {
			tok = RandomToken()
		}
		cfg.Admin.Token = tok
		changed = true
	}

	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("generated config invalid: %w", err)
	}
	if changed {
		if err := cfg.Save(o.ConfigPath); err != nil {
			return err
		}
	}
	fmt.Printf("✔ config at %s\n", o.ConfigPath)
	if cfg.Admin.Token != "" {
		fmt.Printf("  admin token: %s\n", cfg.Admin.Token)
	}
	if cfg.Server.Domain != "" {
		ips, err := net.LookupIP(cfg.Server.Domain)
		if err != nil || len(ips) == 0 {
			fmt.Printf("  ⚠ %s does not resolve yet — create an A/AAAA record pointing at this VPS\n", cfg.Server.Domain)
		} else {
			fmt.Printf("  ✔ %s resolves (%v)\n", cfg.Server.Domain, ips)
		}
	}
	fmt.Println("next: run 'sudo supp server' (systemd unit: scripts/supp.service)")
	return nil
}

// RandomToken returns 32 hex chars of crypto randomness.
func RandomToken() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand unavailable: " + err.Error())
	}
	return hex.EncodeToString(b)
}

func readLine() string {
	r := bufio.NewReader(os.Stdin)
	line, _ := r.ReadString('\n')
	return strings.TrimSpace(line)
}
