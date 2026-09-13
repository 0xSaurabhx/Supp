package wg

import (
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/0xsaurabhx/Supp/internal/config"
	"github.com/0xsaurabhx/Supp/internal/store"
)

// Store is the persistence surface the service needs (implemented by
// *store.Store; an interface keeps the package testable).
type Store interface {
	CreateWgPeer(name, pub, priv, ip string, fullTunnel bool, clientID int64) (*store.WgPeer, error)
	ListWgPeers() ([]store.WgPeer, error)
	WgPeerByID(id int64) (*store.WgPeer, error)
	WgPeerByName(name string) (*store.WgPeer, error)
	DeleteWgPeer(id int64) error
	SetWgPeerActive(id int64, active bool) error
	UpdateWgPeerStats(id int64, rx, tx uint64, handshake time.Time) error
	WgPeerIPs() (map[string]bool, error)
}

// Service orchestrates config, store and the kernel manager.
type Service struct {
	Cfg     config.WG
	Store   Store
	Mgr     Manager // nil when kernel management is unavailable
	Domain  string  // server.domain, used for the default endpoint
	DataDir string
	Log     *slog.Logger
}

// NewService builds a service; call EnsureKernel to attach the platform
// manager (it stays nil on unsupported platforms).
func NewService(cfg config.WG, st Store, domain, dataDir string, log *slog.Logger) *Service {
	return &Service{Cfg: cfg, Store: st, Domain: domain, DataDir: dataDir, Log: log}
}

// EnsureKernel creates the manager if the platform supports it. When the
// kernel side is unavailable, Mgr stays nil and only conf/QR generation works.
func (s *Service) EnsureKernel() error {
	if s.Mgr != nil {
		return nil
	}
	m, err := NewManager(s.Cfg.Interface)
	if err != nil {
		return err
	}
	s.Mgr = m
	return nil
}

func (s *Service) keyPath() string { return s.DataDir + "/wg/server.key" }

// LoadOrCreateServerKey reads the server private key from disk, generating
// and persisting it (0600) on first use.
func (s *Service) LoadOrCreateServerKey() (string, error) {
	b, err := readFile(s.keyPath())
	if err == nil && len(strings.TrimSpace(string(b))) > 0 {
		return strings.TrimSpace(string(b)), nil
	}
	priv, err := GeneratePrivateKey()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(s.keyPath()), 0o700); err != nil {
		return "", err
	}
	if err := writeFile(s.keyPath(), []byte(priv+"\n"), 0o600); err != nil {
		return "", fmt.Errorf("persist server key: %w", err)
	}
	return priv, nil
}

// Endpoint is host:port peers dial.
func (s *Service) Endpoint() string { return s.Cfg.EffectiveEndpoint(s.Domain) }

// Enable brings the whole VPN up: key, interface, routing, peer reconcile.
func (s *Service) Enable() error {
	if err := s.EnsureKernel(); err != nil {
		return err
	}
	priv, err := s.LoadOrCreateServerKey()
	if err != nil {
		return err
	}
	sip, err := ServerIP(s.Cfg.Subnet)
	if err != nil {
		return err
	}
	prefix, err := netip.ParsePrefix(s.Cfg.Subnet)
	if err != nil {
		return err
	}
	if err := s.Mgr.EnsureInterface(priv, s.Cfg.Port, sip, prefix.Bits()); err != nil {
		return err
	}
	if err := s.Mgr.SetupRouting(s.Cfg.Subnet); err != nil {
		return err
	}
	if err := s.reconcilePeers(); err != nil {
		return err
	}
	s.Log.Info("wireguard enabled", "interface", s.Cfg.Interface, "port", s.Cfg.Port,
		"subnet", s.Cfg.Subnet, "endpoint", s.Endpoint())
	return nil
}

// Disable tears down routing and the interface; peer rows are kept.
func (s *Service) Disable() error {
	if s.Mgr == nil {
		return ErrUnsupported
	}
	_ = s.Mgr.TeardownRouting(s.Cfg.Subnet)
	return s.Mgr.CloseInterface()
}

// kernelPeers builds the desired kernel peer list from the store.
func (s *Service) kernelPeers() ([]KernelPeer, error) {
	peers, err := s.Store.ListWgPeers()
	if err != nil {
		return nil, err
	}
	out := make([]KernelPeer, 0, len(peers))
	for _, p := range peers {
		out = append(out, KernelPeer{
			PublicKey: p.PublicKey,
			AllowedIP: p.IP + "/32",
			Remove:    !p.Active, // revoked peers are pulled from the kernel
		})
	}
	return out, nil
}

func (s *Service) reconcilePeers() error {
	if s.Mgr == nil {
		return ErrUnsupported
	}
	kp, err := s.kernelPeers()
	if err != nil {
		return err
	}
	return s.Mgr.ApplyPeers(kp)
}

// AddPeer creates a peer row, allocates an IP and applies it to the kernel.
func (s *Service) AddPeer(name string, fullTunnel bool, clientID int64) (*store.WgPeer, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, fmt.Errorf("peer name required")
	}
	if _, err := s.Store.WgPeerByName(name); err == nil {
		return nil, fmt.Errorf("peer %q already exists", name)
	}
	taken, err := s.Store.WgPeerIPs()
	if err != nil {
		return nil, err
	}
	if sip, err := ServerIP(s.Cfg.Subnet); err == nil {
		taken[sip] = true // reserve the gateway address
	}
	ip, err := AllocIP(s.Cfg.Subnet, taken)
	if err != nil {
		return nil, err
	}
	priv, err := GeneratePrivateKey()
	if err != nil {
		return nil, err
	}
	pub, err := PublicKey(priv)
	if err != nil {
		return nil, err
	}
	p, err := s.Store.CreateWgPeer(name, pub, priv, ip, fullTunnel, clientID)
	if err != nil {
		return nil, err
	}
	if s.Mgr != nil {
		if err := s.reconcilePeers(); err != nil {
			s.Log.Warn("peer added but kernel apply failed", "peer", name, "err", err)
		}
	}
	return p, nil
}

// RemovePeer deletes a peer row and pulls it from the kernel.
func (s *Service) RemovePeer(id int64) error {
	if err := s.Store.DeleteWgPeer(id); err != nil {
		return err
	}
	if s.Mgr != nil {
		return s.reconcilePeers()
	}
	return nil
}

// SetPeerActive toggles a peer (revoke = remove from kernel, keep row).
func (s *Service) SetPeerActive(id int64, active bool) error {
	if err := s.Store.SetWgPeerActive(id, active); err != nil {
		return err
	}
	if s.Mgr != nil {
		return s.reconcilePeers()
	}
	return nil
}

// PeerConf renders the wg-quick config for one peer.
func (s *Service) PeerConf(p *store.WgPeer) (string, error) {
	serverPriv, err := s.LoadOrCreateServerKey()
	if err != nil {
		return "", err
	}
	serverPub, err := PublicKey(serverPriv)
	if err != nil {
		return "", err
	}
	sip, err := ServerIP(s.Cfg.Subnet)
	if err != nil {
		return "", err
	}
	split := s.Cfg.SplitNetworks
	if p.FullTunnel {
		split = nil
	}
	return PeerConfig{
		PrivateKey:    p.PrivateKey,
		Address:       p.IP,
		ServerPub:     serverPub,
		Endpoint:      s.Endpoint(),
		FullTunnel:    p.FullTunnel,
		SplitDNSIP:    sip,
		SplitNetworks: split,
	}.Render(), nil
}

// RefreshStats pulls kernel counters into the store for all peers.
func (s *Service) RefreshStats() error {
	if s.Mgr == nil {
		return nil
	}
	peers, err := s.Store.ListWgPeers()
	if err != nil {
		return err
	}
	for _, p := range peers {
		rt, err := s.Mgr.Runtime(p.PublicKey)
		if err != nil {
			continue // peer absent (revoked) — fine
		}
		_ = s.Store.UpdateWgPeerStats(p.ID, rt.RxBytes, rt.TxBytes, rt.LastHandsha)
	}
	return nil
}

// Loop refreshes stats periodically until done closes.
func (s *Service) Loop(done <-chan struct{}) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-done:
			return
		case <-t.C:
			_ = s.RefreshStats()
		}
	}
}

// Status is a dashboard-facing summary.
type Status struct {
	Interface string         `json:"interface"`
	Endpoint  string         `json:"endpoint"`
	Port      int            `json:"port"`
	Subnet    string         `json:"subnet"`
	ServerIP  string         `json:"server_ip"`
	Peers     []store.WgPeer `json:"peers"`
	Up        bool           `json:"up"`
}

// Status gathers the current VPN view. Up is true when a kernel manager is
// attached (i.e. supp runs on a Linux host with wgctrl access).
func (s *Service) Status() Status {
	st := Status{
		Interface: s.Cfg.Interface,
		Endpoint:  s.Endpoint(),
		Port:      s.Cfg.Port,
		Subnet:    s.Cfg.Subnet,
		Up:        s.Mgr != nil,
	}
	if sip, err := ServerIP(s.Cfg.Subnet); err == nil {
		st.ServerIP = sip
	}
	if peers, err := s.Store.ListWgPeers(); err == nil {
		st.Peers = peers
	}
	return st
}
