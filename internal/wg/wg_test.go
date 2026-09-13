package wg

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenerateAndDerive(t *testing.T) {
	priv, err := GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	if len(priv) != 44 || priv[43] != '=' {
		t.Fatalf("private key shape: %q", priv)
	}
	pub, err := PublicKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	if len(pub) != 44 {
		t.Fatalf("public key shape: %q", pub)
	}
	// Deterministic derivation: same private key -> same public key.
	pub2, err := PublicKey(priv)
	if err != nil || pub2 != pub {
		t.Fatalf("derivation not deterministic: %q vs %q", pub, pub2)
	}
	if _, err := PublicKey("not-a-key"); err == nil {
		t.Fatal("expected error for invalid private key")
	}
}

func TestRenderFullTunnel(t *testing.T) {
	conf := PeerConfig{
		PrivateKey: "PRIV", Address: "10.66.0.2", ServerPub: "SRVPUB",
		Endpoint: "vpn.example.com:51820", FullTunnel: true, SplitDNSIP: "10.66.0.1",
	}.Render()
	for _, want := range []string{
		"[Interface]", "PrivateKey = PRIV", "Address = 10.66.0.2/32",
		"DNS = 10.66.0.1", "[Peer]", "PublicKey = SRVPUB",
		"Endpoint = vpn.example.com:51820", "AllowedIPs = 0.0.0.0/0, ::/0",
		"PersistentKeepalive = 25",
	} {
		if !strings.Contains(conf, want) {
			t.Errorf("conf missing %q\n%s", want, conf)
		}
	}
}

func TestRenderSplit(t *testing.T) {
	conf := PeerConfig{
		PrivateKey: "PRIV", Address: "10.66.0.3", ServerPub: "SRVPUB",
		Endpoint: "vpn.example.com:51820", FullTunnel: false, SplitDNSIP: "10.66.0.1",
		SplitNetworks: []string{"192.168.1.0/24", "bogus", "10.0.0.0/8"},
	}.Render()
	if !strings.Contains(conf, "AllowedIPs = 0.0.0.0/0, 10.0.0.0/8, 192.168.1.0/24") {
		t.Errorf("split AllowedIPs wrong:\n%s", conf)
	}
}

func TestAllocIP(t *testing.T) {
	taken := map[string]bool{"10.66.0.1": true}
	ip, err := AllocIP("10.66.0.0/24", taken)
	if err != nil || ip != "10.66.0.2" {
		t.Fatalf("got %q, %v", ip, err)
	}
	// Exhaust the subnet: /30 has hosts .1 (server) and .2.
	taken["10.66.0.2"] = true
	if _, err := AllocIP("10.66.0.0/30", taken); err == nil {
		t.Fatal("expected exhaustion error on /30")
	}
	if _, err := AllocIP("garbage", nil); err == nil {
		t.Fatal("expected error for bad CIDR")
	}
}

func TestServerIP(t *testing.T) {
	ip, err := ServerIP("10.66.0.0/24")
	if err != nil || ip != "10.66.0.1" {
		t.Fatalf("got %q, %v", ip, err)
	}
}

func TestLoadOrCreateServerKey(t *testing.T) {
	dir := t.TempDir()
	s := &Service{DataDir: dir}
	k1, err := s.LoadOrCreateServerKey()
	if err != nil {
		t.Fatal(err)
	}
	k2, err := s.LoadOrCreateServerKey()
	if err != nil || k1 != k2 {
		t.Fatalf("key not stable across loads: %q vs %q", k1, k2)
	}
	path := filepath.Join(dir, "wg", "server.key")
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("key perm = %v, want 0600", st.Mode().Perm())
	}
}

func TestQRPNG(t *testing.T) {
	png, err := QRPNG("test-config", 256)
	if err != nil || len(png) == 0 {
		t.Fatalf("qr png: %v", err)
	}
	if png[0] != 0x89 || png[1] != 'P' {
		t.Fatal("not a PNG")
	}
}

func TestQRTerminal(t *testing.T) {
	art, err := QRTerminal("test-config")
	if err != nil || !strings.Contains(art, "\n") {
		t.Fatalf("terminal qr: %v", err)
	}
}
