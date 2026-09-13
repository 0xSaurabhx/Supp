//go:build linux

package wg

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// linuxManager drives the kernel WireGuard interface via wgctrl (netlink)
// and installs NAT with nft (preferred) or iptables.
type linuxManager struct {
	iface string
	cl    *wgctrl.Client
	mu    sync.Mutex
}

func newKernelManager(iface string) (Manager, error) {
	cl, err := wgctrl.New()
	if err != nil {
		return nil, fmt.Errorf("wgctrl: %w (root? kernel wireguard loaded?)", err)
	}
	return &linuxManager{iface: iface, cl: cl}, nil
}

// EnsureInterface creates the link if missing, then applies private key,
// listen port and address. Safe to re-run (idempotent reconcile).
func (m *linuxManager) EnsureInterface(privateKey string, port int, ip string, plen int) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	devs, err := m.cl.Devices()
	if err != nil {
		return fmt.Errorf("list wg devices: %w", err)
	}
	found := false
	for _, d := range devs {
		if d.Name == m.iface {
			found = true
			break
		}
	}
	if !found {
		// wgctrl cannot create links; iproute2 is a hard dep on any VPS.
		if err := run("ip", "link", "add", "dev", m.iface, "type", "wireguard"); err != nil {
			return fmt.Errorf("create %s: %w (wireguard kernel module available?)", m.iface, err)
		}
	}
	key, err := wgtypes.ParseKey(privateKey)
	if err != nil {
		return fmt.Errorf("server key: %w", err)
	}
	if err := m.cl.ConfigureDevice(m.iface, wgtypes.Config{
		PrivateKey: &key,
		ListenPort: &port,
	}); err != nil {
		return fmt.Errorf("configure %s: %w", m.iface, err)
	}
	addr := fmt.Sprintf("%s/%d", ip, plen)
	if err := run("ip", "addr", "replace", addr, "dev", m.iface); err != nil {
		return fmt.Errorf("assign %s: %w", addr, err)
	}
	if err := run("ip", "link", "set", "up", "dev", m.iface); err != nil {
		return fmt.Errorf("up %s: %w", m.iface, err)
	}
	return nil
}

// ApplyPeers reconciles the kernel peer list to exactly the desired set.
func (m *linuxManager) ApplyPeers(peers []KernelPeer) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	dev, err := m.cl.Device(m.iface)
	if err != nil {
		return fmt.Errorf("device %s: %w", m.iface, err)
	}
	existing := map[string]bool{}
	for _, p := range dev.Peers {
		existing[p.PublicKey.String()] = true
	}
	desired := map[string]bool{}
	var cfgs []wgtypes.PeerConfig
	for _, kp := range peers {
		pub, err := wgtypes.ParseKey(kp.PublicKey)
		if err != nil {
			return fmt.Errorf("peer key: %w", err)
		}
		if kp.Remove {
			if existing[kp.PublicKey] {
				cfgs = append(cfgs, wgtypes.PeerConfig{PublicKey: pub, Remove: true})
			}
			continue
		}
		desired[kp.PublicKey] = true
		_, ipnet, err := net.ParseCIDR(kp.AllowedIP)
		if err != nil {
			return fmt.Errorf("peer allowedips %q: %w", kp.AllowedIP, err)
		}
		// Only send an update when the peer is new; AllowedIPs use ReplaceIPs
		// so any (re)add fully overwrites prior state.
		if !existing[kp.PublicKey] {
			cfgs = append(cfgs, wgtypes.PeerConfig{
				PublicKey:         pub,
				AllowedIPs:        []net.IPNet{*ipnet},
				ReplaceAllowedIPs: true,
			})
		}
	}
	for pub := range existing {
		if !desired[pub] {
			k, _ := wgtypes.ParseKey(pub)
			cfgs = append(cfgs, wgtypes.PeerConfig{PublicKey: k, Remove: true})
		}
	}
	if len(cfgs) == 0 {
		return nil
	}
	if err := m.cl.ConfigureDevice(m.iface, wgtypes.Config{Peers: cfgs}); err != nil {
		return fmt.Errorf("apply peers: %w", err)
	}
	return nil
}

// Runtime fetches live counters for one peer.
func (m *linuxManager) Runtime(publicKey string) (PeerRuntime, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	dev, err := m.cl.Device(m.iface)
	if err != nil {
		return PeerRuntime{}, err
	}
	for _, p := range dev.Peers {
		if p.PublicKey.String() == publicKey {
			return PeerRuntime{
				RxBytes:     uint64(p.ReceiveBytes),
				TxBytes:     uint64(p.TransmitBytes),
				LastHandsha: p.LastHandshakeTime,
			}, nil
		}
	}
	return PeerRuntime{}, fmt.Errorf("peer %s not present", publicKey)
}

func (m *linuxManager) CloseInterface() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return run("ip", "link", "del", "dev", m.iface)
}

// SetupRouting enables ip_forward and NAT masquerade for the tunnel.
// Prefers nftables (atomic table replace); falls back to iptables.
func (m *linuxManager) SetupRouting(tunnelCIDR string) error {
	_ = writeSysctl("net/ipv4/ip_forward", "1")
	if hasBinary("nft") {
		return m.setupNft(tunnelCIDR)
	}
	if hasBinary("iptables") {
		return m.setupIptables(tunnelCIDR)
	}
	return fmt.Errorf("neither nft nor iptables available for NAT setup")
}

func (m *linuxManager) setupNft(tunnelCIDR string) error {
	const table = "supp_wg"
	script := fmt.Sprintf(`add table inet %s
delete table inet %s
add table inet %s
table inet %s {
	chain postrouting {
		type nat hook postrouting priority srcnat; policy accept;
		ip saddr %s masquerade comment "supp-wg"
	}
	chain forward {
		type filter hook forward priority filter; policy accept;
		ip saddr %s accept comment "supp-wg"
		ip daddr %s ct state established,related accept comment "supp-wg"
	}
}
`, table, table, table, table, tunnelCIDR, tunnelCIDR, tunnelCIDR)
	if err := runStdin("nft", []byte(script), "-f", "-"); err != nil {
		return fmt.Errorf("nft: %w", err)
	}
	return nil
}

func (m *linuxManager) setupIptables(tunnelCIDR string) error {
	iface := outboundInterface()
	if iface == "" {
		iface = "eth0"
	}
	if err := run("sysctl", "-w", "net.ipv4.ip_forward=1"); err != nil {
		return fmt.Errorf("ip_forward: %w", err)
	}
	rules := [][]string{
		{"nat", "POSTROUTING", "-s", tunnelCIDR, "-o", iface, "-j", "MASQUERADE", "-m", "comment", "--comment", "supp-wg"},
		{"filter", "FORWARD", "-i", m.iface, "-j", "ACCEPT", "-m", "comment", "--comment", "supp-wg"},
		{"filter", "FORWARD", "-o", m.iface, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT", "-m", "comment", "--comment", "supp-wg"},
	}
	for _, r := range rules {
		check := append([]string{"-t", r[0], "-C", r[1]}, r[2:]...)
		if err := run("iptables", check...); err != nil {
			add := append([]string{"-t", r[0], "-A", r[1]}, r[2:]...)
			if err := run("iptables", add...); err != nil {
				return fmt.Errorf("iptables -A %s: %w", r[1], err)
			}
		}
	}
	return nil
}

func (m *linuxManager) TeardownRouting(tunnelCIDR string) error {
	if hasBinary("nft") {
		_ = run("nft", "delete", "table", "inet", "supp_wg")
	}
	if hasBinary("iptables") {
		iface := outboundInterface()
		if iface == "" {
			iface = "eth0"
		}
		_ = run("iptables", "-t", "nat", "-D", "POSTROUTING", "-s", tunnelCIDR, "-o", iface, "-j", "MASQUERADE", "-m", "comment", "--comment", "supp-wg")
		_ = run("iptables", "-D", "FORWARD", "-i", m.iface, "-j", "ACCEPT", "-m", "comment", "--comment", "supp-wg")
		_ = run("iptables", "-D", "FORWARD", "-o", m.iface, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT", "-m", "comment", "--comment", "supp-wg")
	}
	return nil
}

// run executes a command, returning an error with stderr attached.
func run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	var errOut strings.Builder
	cmd.Stderr = &errOut
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(errOut.String()))
	}
	return nil
}

// runStdin pipes stdin to the command (used for `nft -f -`).
func runStdin(name string, input []byte, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdin = bytesReader(input)
	var errOut strings.Builder
	cmd.Stderr = &errOut
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(errOut.String()))
	}
	return nil
}

func hasBinary(name string) bool {
	p, err := exec.LookPath(name)
	return err == nil && p != ""
}

func writeSysctl(path, val string) error {
	f := "/proc/sys/" + path
	if err := os.WriteFile(f, []byte(val+"\n"), 0o644); err != nil {
		// Fall back to sysctl binary.
		return run("sysctl", "-w", strings.ReplaceAll(path, "/", ".")+"="+val)
	}
	return nil
}

func outboundInterface() string {
	out, err := exec.Command("ip", "route", "show", "default").Output()
	if err != nil {
		return ""
	}
	fields := strings.Fields(string(out))
	for i, f := range fields {
		if f == "dev" && i+1 < len(fields) {
			return fields[i+1]
		}
	}
	return ""
}
