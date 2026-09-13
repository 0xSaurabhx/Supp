package store

import (
	"path/filepath"
	"testing"
	"time"
)

func openTestWGStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "test.db"), false, 720*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestWgPeerCRUD(t *testing.T) {
	s := openTestWGStore(t)

	p, err := s.CreateWgPeer("laptop", "PUB", "PRIV", "10.66.0.2", true, 0)
	if err != nil {
		t.Fatal(err)
	}
	if p.ID == 0 || !p.Active || !p.FullTunnel {
		t.Fatalf("unexpected peer: %+v", p)
	}

	// Unique name and IP constraints.
	if _, err := s.CreateWgPeer("laptop", "PUB2", "PRIV2", "10.66.0.3", true, 0); err == nil {
		t.Fatal("expected duplicate-name error")
	}
	if _, err := s.CreateWgPeer("phone", "PUB2", "PRIV2", "10.66.0.2", true, 0); err == nil {
		t.Fatal("expected duplicate-ip error")
	}

	got, err := s.WgPeerByName("laptop")
	if err != nil || got.PrivateKey != "PRIV" || got.PublicKey != "PUB" {
		t.Fatalf("by name: %+v, %v", got, err)
	}
	got2, err := s.WgPeerByID(p.ID)
	if err != nil || got2.Name != "laptop" {
		t.Fatalf("by id: %+v, %v", got2, err)
	}
	if _, err := s.WgPeerByName("nope"); err != ErrNotFound {
		t.Fatalf("want ErrNotFound, got %v", err)
	}

	// Revoke / restore.
	if err := s.SetWgPeerActive(p.ID, false); err != nil {
		t.Fatal(err)
	}
	got, _ = s.WgPeerByID(p.ID)
	if got.Active {
		t.Fatal("expected revoked")
	}
	if err := s.SetWgPeerActive(p.ID, true); err != nil {
		t.Fatal(err)
	}

	// Stats.
	hs := time.Unix(1700000000, 0)
	if err := s.UpdateWgPeerStats(p.ID, 100, 200, hs); err != nil {
		t.Fatal(err)
	}
	got, _ = s.WgPeerByID(p.ID)
	if got.RxBytes != 100 || got.TxBytes != 200 || !got.LastHandsha.Equal(hs) {
		t.Fatalf("stats: %+v", got)
	}

	// IP listing includes rows.
	ips, err := s.WgPeerIPs()
	if err != nil || !ips["10.66.0.2"] {
		t.Fatalf("ips: %v, %v", ips, err)
	}

	// Delete.
	if err := s.DeleteWgPeer(p.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.WgPeerByID(p.ID); err != ErrNotFound {
		t.Fatalf("want ErrNotFound after delete, got %v", err)
	}
}

func TestWgPeerHandshakeHelpers(t *testing.T) {
	s := openTestWGStore(t)
	p, _ := s.CreateWgPeer("x", "PUB", "PRIV", "10.66.0.2", false, 0)
	if p.HasHandshake() {
		t.Fatal("fresh peer must have no handshake")
	}
	if p.HandshakeAgo() != "never" {
		t.Fatalf("ago = %q", p.HandshakeAgo())
	}
}
