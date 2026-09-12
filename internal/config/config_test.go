package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDefaultsValidate(t *testing.T) {
	if err := Default().Validate(); err != nil {
		t.Fatalf("defaults invalid: %v", err)
	}
}

func TestLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config.toml")
	cfg := Default()
	cfg.Server.Domain = "dns.example.com"
	cfg.Admin.Token = "abc123"
	cfg.Block.Allowlist = []string{"keep.example.com"}
	if err := cfg.Save(p); err != nil {
		t.Fatal(err)
	}
	got, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if got.Server.Domain != "dns.example.com" || got.Admin.Token != "abc123" {
		t.Fatalf("round trip mismatch: %+v", got.Server)
	}
	if got.DNS.Cache.MinTTL.D() != 60*time.Second {
		t.Fatalf("min ttl = %v", got.DNS.Cache.MinTTL.D())
	}
}

func TestLoadInvalidValueFails(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "c.toml")
	// Config merges over defaults; an explicitly invalid value must fail.
	_ = os.WriteFile(p, []byte(`
[dns.cache]
size = 0
`), 0o600)
	if _, err := Load(p); err == nil {
		t.Fatal("expected error for cache.size = 0")
	}
}

func TestSaveFilePerms(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "sub", "config.toml")
	if err := Default().Save(p); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("perm = %v, want 0600", st.Mode().Perm())
	}
}
