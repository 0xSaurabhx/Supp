package dns

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"
)

// BrowserPool performs DoH POSTs with a browser-like TLS fingerprint.
// It is a last-resort transport: used only when every configured upstream
// is unhealthy, so the fingerprint stays cold and unused in normal
// operation.
type BrowserPool struct {
	mu      sync.Mutex
	clients []*browserClient
	idx     int
}

// browserClient is one uTLS-based DoH client.
type browserClient struct {
	http *http.Client
	dial func(ctx context.Context, network, addr string) (net.Conn, error)
}

// NewBrowserPool builds a pool of n clients using profile (e.g. "chrome").
func NewBrowserPool(n int) (*BrowserPool, error) {
	if n <= 0 {
		n = 2
	}
	pool := &BrowserPool{}
	for i := 0; i < n; i++ {
		bc, err := newBrowserClient()
		if err != nil {
			return nil, err
		}
		pool.clients = append(pool.clients, bc)
	}
	return pool, nil
}

func newBrowserClient() (*browserClient, error) {
	bc := &browserClient{}
	bc.dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
		// Wrap TCP dials with uTLS Chrome fingerprint; hostname from SNI.
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			host = addr
		}
		raw, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", addr)
		if err != nil {
			return nil, err
		}
		cfg := &utls.Config{ServerName: host, NextProtos: []string{"h2", "http/1.1"}}
		uconn := utls.UClient(raw, cfg, utls.HelloChrome_Auto)
		if err := uconn.HandshakeContext(ctx); err != nil {
			raw.Close()
			return nil, err
		}
		return uconn, nil
	}
	t := &http.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return bc.dial(ctx, network, addr)
		},
		ForceAttemptHTTP2:   true,
		IdleConnTimeout:     90 * time.Second,
		MaxIdleConns:        2,
		MaxIdleConnsPerHost: 2,
	}
	bc.http = &http.Client{Transport: t, Timeout: 8 * time.Second}
	return bc, nil
}

// Post sends wire as an application/dns-message POST to target.
func (p *BrowserPool) Post(ctx context.Context, target string, wire []byte) ([]byte, error) {
	p.mu.Lock()
	bc := p.clients[p.idx%len(p.clients)]
	p.idx++
	p.mu.Unlock()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(wire))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
	resp, err := bc.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("browser-doh status %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 64<<10))
}

// Close releases idle connections.
func (p *BrowserPool) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, c := range p.clients {
		if tr, ok := c.http.Transport.(*http.Transport); ok {
			tr.CloseIdleConnections()
		}
	}
}

var errBrowserDisabled = errors.New("browser upstream disabled")

// Ensure tls import is used (kept for future pinned-CA option).
var _ = tls.VersionTLS12
