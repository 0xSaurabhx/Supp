package wg

import (
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
)

// PeerConfig is the data needed to render a client .conf file.
type PeerConfig struct {
	PrivateKey  string // client private key (base64)
	Address     string // client tunnel IP, e.g. 10.66.0.2
	ServerPub   string // server public key (base64)
	Endpoint    string // host:port of the server
	FullTunnel  bool
	SplitDNSIP  string      // server tunnel IP used as the DNS resolver
	SplitNetworks []string  // extra CIDRs when split-tunnel
}

// AllowedIPs returns the routes the client pushes into the tunnel.
func (p PeerConfig) AllowedIPs() string {
	if p.FullTunnel {
		return "0.0.0.0/0, ::/0"
	}
	nets := []string{"0.0.0.0/0"} // DNS via tunnel; add explicit networks below
	seen := map[string]bool{"0.0.0.0/0": true}
	for _, n := range p.SplitNetworks {
		n = strings.TrimSpace(n)
		if n == "" || seen[n] {
			continue
		}
		if _, err := netip.ParsePrefix(n); err != nil {
			continue
		}
		seen[n] = true
		nets = append(nets, n)
	}
	sort.Strings(nets)
	return strings.Join(nets, ", ")
}

// Render produces the standard wg-quick .conf text for the peer.
func (p PeerConfig) Render() string {
	var b strings.Builder
	b.WriteString("[Interface]\n")
	fmt.Fprintf(&b, "PrivateKey = %s\n", p.PrivateKey)
	fmt.Fprintf(&b, "Address = %s/32\n", p.Address)
	fmt.Fprintf(&b, "DNS = %s\n", p.SplitDNSIP)
	b.WriteString("\n[Peer]\n")
	fmt.Fprintf(&b, "PublicKey = %s\n", p.ServerPub)
	fmt.Fprintf(&b, "Endpoint = %s\n", p.Endpoint)
	fmt.Fprintf(&b, "AllowedIPs = %s\n", p.AllowedIPs())
	b.WriteString("PersistentKeepalive = 25\n")
	return b.String()
}

// AllocIP picks the first free host address in subnet, skipping taken,
// the server address (first host) and — for IPv4 — the broadcast address.
func AllocIP(subnet string, taken map[string]bool) (string, error) {
	prefix, err := netip.ParsePrefix(strings.TrimSpace(subnet))
	if err != nil {
		return "", fmt.Errorf("subnet %q: %w", subnet, err)
	}
	prefix = prefix.Masked()
	for addr := prefix.Addr().Next(); prefix.Contains(addr); addr = addr.Next() {
		if prefix.Addr().Is4() && isBroadcast(prefix, addr) {
			continue
		}
		s := addr.String()
		if taken[s] {
			continue
		}
		return s, nil
	}
	return "", fmt.Errorf("subnet %s has no free addresses", subnet)
}

// isBroadcast reports whether addr is the last address of an IPv4 prefix
// (host bits all ones).
func isBroadcast(prefix netip.Prefix, addr netip.Addr) bool {
	net4 := prefix.Addr().As4()
	a := addr.As4()
	hostBits := 32 - prefix.Bits()
	if hostBits == 0 || hostBits > 31 {
		return false
	}
	var last [4]byte
	copy(last[:], net4[:])
	remaining := hostBits
	for i := 3; i >= 0 && remaining > 0; i-- {
		take := remaining
		if take > 8 {
			take = 8
		}
		last[i] = net4[i] | byte(0xff>>(8-take))
		remaining -= take
	}
	return last == a
}

// ServerIP is the first host of the subnet (the tunnel gateway).
func ServerIP(subnet string) (string, error) {
	prefix, err := netip.ParsePrefix(strings.TrimSpace(subnet))
	if err != nil {
		return "", fmt.Errorf("subnet %q: %w", subnet, err)
	}
	first := prefix.Addr().Next()
	if !prefix.Contains(first) {
		return "", fmt.Errorf("subnet %s too small", subnet)
	}
	return first.String(), nil
}

// SplitEndpointPort splits "host" or "host:port", defaulting the port.
func SplitEndpointPort(ep string, defaultPort int) (host string, port int) {
	host = ep
	port = defaultPort
	if i := strings.LastIndexByte(ep, ':'); i >= 0 {
		if p, err := strconv.Atoi(ep[i+1:]); err == nil {
			host = ep[:i]
			port = p
		}
	}
	return host, port
}
