//go:build !linux

package wg

// otherManager stubs the Manager interface on platforms without kernel
// WireGuard (macOS, Windows, BSD). Config rendering and QR generation keep
// working; only kernel mutations fail.
type otherManager struct{ iface string }

func newKernelManager(iface string) (Manager, error) {
	return &otherManager{iface: iface}, nil
}

func (m *otherManager) EnsureInterface(string, int, string, int) error { return ErrUnsupported }
func (m *otherManager) ApplyPeers([]KernelPeer) error                  { return ErrUnsupported }
func (m *otherManager) Runtime(string) (PeerRuntime, error)            { return PeerRuntime{}, ErrUnsupported }
func (m *otherManager) CloseInterface() error                          { return ErrUnsupported }
func (m *otherManager) SetupRouting(string) error                      { return ErrUnsupported }
func (m *otherManager) TeardownRouting(string) error                   { return ErrUnsupported }
