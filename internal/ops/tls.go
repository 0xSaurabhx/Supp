// Package ops — TLS: ACME (autocert) for a public domain; self-signed
// fallback for local testing without a domain.
package ops

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
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

// GetCerts returns autocert-managed certificates for the configured domain,
// or a self-signed certificate when no domain is set or ACME fails.
func GetCerts(ctx context.Context, cfg *config.Config, log *slog.Logger) (*TLSCerts, error) {
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

	// Fast path: try cached cert first.
	cert, err := mgr.GetCertificate(&tls.ClientHelloInfo{ServerName: host})
	if err == nil {
		return &TLSCerts{Cert: cert, Domain: host, Manager: mgr}, nil
	}

	// Start HTTP-01 challenge server on :80 to answer ACME validation.
	acmeSrv := &http.Server{
		Addr:    ":80",
		Handler: mgr.HTTPHandler(nil),
	}
	go func() {
		_ = acmeSrv.ListenAndServe()
	}()
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_ = acmeSrv.Shutdown(shutdownCtx)
		cancel()
	}()

	log.Info("obtaining certificate (may take ~20s)", "domain", host)
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		cert, err = mgr.GetCertificate(&tls.ClientHelloInfo{ServerName: host})
		if err == nil {
			log.Info("certificate obtained successfully", "domain", host)
			return &TLSCerts{Cert: cert, Domain: host, Manager: mgr}, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}

	log.Warn("could not obtain ACME certificate; falling back to self-signed certificate", "err", err)
	fallbackCert, fallbackErr := selfSigned(host)
	if fallbackErr != nil {
		return nil, fmt.Errorf("self-signed fallback failed: %w", fallbackErr)
	}
	return &TLSCerts{Cert: fallbackCert, Domain: host, SelfSign: true, Manager: mgr}, nil
}

// ACMEHosts exposes the whitelist for the HTTP-01 challenge server.
func (t *TLSCerts) ACMEHosts() []string {
	if t == nil || t.Domain == "" || t.SelfSign {
		return nil
	}
	return []string{t.Domain}
}

func acmeEmail() string {
	return os.Getenv("SUPP_ACME_EMAIL")
}

// errNoACME is returned when a cert is requested but ACME cannot run.
var errNoACME = errors.New("acme unavailable")

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
