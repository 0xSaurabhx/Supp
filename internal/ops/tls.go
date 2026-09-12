// Package ops — TLS: ACME (autocert) for a public domain; self-signed
// fallback for local testing without a domain.
package ops

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/acme/autocert"

	"github.com/0xsaurabhx/Supp/internal/config"
)

// TLSCerts holds the certificate used by DoT and DoH listeners plus the
// autocert manager that keeps it renewed.
type TLSCerts struct {
	Cert     *tls.Certificate
	Domain   string
	SelfSign bool
	Manager  *autocert.Manager
}

// GetCerts initializes autocert for the configured domain (or self-signed cert for local mode).
func GetCerts(cfg *config.Config, log *slog.Logger) (*TLSCerts, error) {
	if cfg.Server.Domain == "" {
		log.Warn("no domain configured; generating self-signed certificate (clients must skip TLS verification)")
		c, err := selfSigned("supp.local")
		if err != nil {
			return nil, err
		}
		return &TLSCerts{Cert: c, Domain: "supp.local", SelfSign: true}, nil
	}

	host := strings.ToLower(cfg.Server.Domain)
	cacheDir := filepath.Join(cfg.Server.DataDir, "certs")
	if err := os.MkdirAll(cacheDir, 0o700); err != nil {
		return nil, err
	}
	mgr := &autocert.Manager{
		Cache:      autocert.DirCache(cacheDir),
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(host),
		Email:      acmeEmail(),
	}

	// Start background HTTP-01 challenge server on :80.
	go func() {
		s := &http.Server{
			Addr:    ":80",
			Handler: mgr.HTTPHandler(nil),
		}
		if err := s.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Warn("acme http-01 server on :80 exited", "err", err)
		}
	}()

	log.Info("autocert TLS manager initialized for domain", "domain", host)
	return &TLSCerts{Domain: host, Manager: mgr}, nil
}

// TLSConfig returns a *tls.Config for the specified NextProtos (ALPN).
func (t *TLSCerts) TLSConfig(nextProtos ...string) *tls.Config {
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: nextProtos,
	}
	if t != nil && t.Manager != nil {
		cfg.GetCertificate = t.Manager.GetCertificate
	} else if t != nil && t.Cert != nil {
		cfg.Certificates = []tls.Certificate{*t.Cert}
	}
	return cfg
}

func acmeEmail() string {
	return os.Getenv("SUPP_ACME_EMAIL")
}

// selfSigned creates a throwaway certificate for local development.
func selfSigned(host string) (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		return nil, err
	}
	tmpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: host, Organization: []string{"Supp"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(825 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{host},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, key.Public(), key)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
		Leaf:        leaf,
	}, nil
}
