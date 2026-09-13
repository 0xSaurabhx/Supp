package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWGDefaultsDisabledValidate(t *testing.T) {
	if err := Default().Validate(); err != nil {
		t.Fatalf("defaults invalid: %v", err)
	}
}

func TestWGValidate(t *testing.T) {
	w := Default().WG
	w.Enabled = true
	if err := w.Validate(); err != nil {
		t.Fatalf("valid wg rejected: %v", err)
	}
	w.Port = 0
	if err := w.Validate(); err == nil {
		t.Fatal("expected port error")
	}
	w = Default().WG
	w.Enabled = true
	w.Subnet = "not-a-cidr"
	if err := w.Validate(); err == nil {
		t.Fatal("expected subnet error")
	}
	w.Subnet = "10.66.0.0/24"
	w.SplitNetworks = []string{"bad"}
	if err := w.Validate(); err == nil {
		t.Fatal("expected split_networks error")
	}
}

func TestEffectiveEndpoint(t *testing.T) {
	w := WG{Port: 51820}
	if got := w.EffectiveEndpoint("dns.example.com"); got != "dns.example.com:51820" {
		t.Fatalf("got %q", got)
	}
	w.Endpoint = "vpn.other.net:1234"
	if got := w.EffectiveEndpoint("dns.example.com"); got != "vpn.other.net:1234" {
		t.Fatalf("got %q", got)
	}
	empty := WG{}
	empty.ApplyDefaults()
	if got := empty.EffectiveEndpoint(""); got != "<server-ip>:51820" {
		t.Fatalf("got %q", got)
	}
}

func TestWGRoundTrip(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config.toml")
	cfg := Default()
	cfg.WG.Enabled = true
	cfg.WG.Endpoint = "vpn.example.com"
	cfg.WG.SplitNetworks = []string{"192.168.1.0/24"}
	if err := cfg.Save(p); err != nil {
		t.Fatal(err)
	}
	got, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if !got.WG.Enabled || got.WG.Endpoint != "vpn.example.com" || got.WG.Interface != "supp0" || got.WG.Port != 51820 {
		t.Fatalf("round trip mismatch: %+v", got.WG)
	}
	if len(got.WG.SplitNetworks) != 1 || got.WG.SplitNetworks[0] != "192.168.1.0/24" {
		t.Fatalf("split networks: %v", got.WG.SplitNetworks)
	}
}

func TestWGApplyDefaults(t *testing.T) {
	var w WG
	w.ApplyDefaults()
	if w.Interface != "supp0" || w.Port != 51820 || w.Subnet != "10.66.0.0/24" {
		t.Fatalf("defaults not applied: %+v", w)
	}
	_ = os.Getenv // keep os import used if trimmed later
}
