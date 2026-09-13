// Package wg implements Supp's WireGuard VPN module (phase 2): key
// management, peer config rendering, QR codes and — on Linux — kernel
// interface management via wgctrl plus NAT/ip_forward plumbing.
package wg

import (
	"fmt"
	"time"
)

// PeerRuntime is the live kernel state of one peer.
type PeerRuntime struct {
	RxBytes     uint64
	TxBytes     uint64
	LastHandsha time.Time
}

// KernelPeer is one peer entry applied to the kernel interface.
type KernelPeer struct {
	PublicKey string // base64
	AllowedIP string // CIDR of the peer's tunnel address
	Remove    bool   // when true the peer is deleted from the interface
}

// Manager mutates the kernel WireGuard state. On non-Linux platforms every
// method returns ErrUnsupported; config/QR generation still works there.
type Manager interface {
	// EnsureInterface creates (or reconfigures) the WireGuard interface with
	// the given private key, listen port and server tunnel address (ip/plen).
	EnsureInterface(privateKey string, port int, ip string, plen int) error
	// ApplyPeers reconciles the full desired peer list (removes extras).
	ApplyPeers(peers []KernelPeer) error
	// Runtime returns live stats for one peer public key.
	Runtime(publicKey string) (PeerRuntime, error)
	// CloseInterface removes the interface.
	CloseInterface() error
	// SetupRouting enables ip_forward and installs NAT masquerade rules.
	SetupRouting(tunnelCIDR string) error
	// TeardownRouting removes the NAT rules created by SetupRouting.
	TeardownRouting(tunnelCIDR string) error
}

// ErrUnsupported is returned by the manager on platforms without kernel
// WireGuard support (everything but Linux).
var ErrUnsupported = fmt.Errorf("kernel wireguard management requires Linux")

// NewManager returns the platform kernel manager.
func NewManager(iface string) (Manager, error) {
	return newKernelManager(iface)
}
