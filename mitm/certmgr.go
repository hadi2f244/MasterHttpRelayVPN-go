// Package mitm implements a MITM CA and per-domain certificate manager for
// intercepting HTTPS traffic. A self-signed CA is generated once and stored
// on disk; per-domain leaf certificates are signed on demand and cached in
// memory. The user must install ca/ca.crt as a trusted root CA once.
package mitm

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"time"
)

var (
	caDir      = findCADir()
	CAKeyFile  = filepath.Join(caDir, "ca.key")
	CACertFile = filepath.Join(caDir, "ca.crt")
)

// findCADir returns the directory where CA files should be stored.
// Priority: $DFT_CA_DIR env, ./ca relative to CWD.
func findCADir() string {
	if v := os.Getenv("DFT_CA_DIR"); v != "" {
		return v
	}
	// Use current working directory
	wd, err := os.Getwd()
	if err != nil {
		return "ca"
	}
	return filepath.Join(wd, "ca")
}

// Manager generates and caches MITM TLS configs.
type Manager struct {
	caKey    *rsa.PrivateKey
	caCert   *x509.Certificate
	caCertRaw []byte

	mu       sync.Mutex
	ctxCache map[string]*tls.Config
}

// NewManager creates or loads the CA key pair.
func NewManager() (*Manager, error) {
	m := &Manager{ctxCache: make(map[string]*tls.Config)}
	if err := m.ensureCA(); err != nil {
		return nil, err
	}
	return m, nil
}

func (m *Manager) ensureCA() error {
	if _, err := os.Stat(CAKeyFile); err == nil {
		// Load existing CA
		keyPEM, err := os.ReadFile(CAKeyFile)
		if err != nil {
			return fmt.Errorf("read ca key: %w", err)
		}
		certPEM, err := os.ReadFile(CACertFile)
		if err != nil {
			return fmt.Errorf("read ca cert: %w", err)
		}
		keyBlock, _ := pem.Decode(keyPEM)
		if keyBlock == nil {
			return fmt.Errorf("invalid PEM in ca.key")
		}
		key, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
		if err != nil {
			return fmt.Errorf("parse ca key: %w", err)
		}
		certBlock, _ := pem.Decode(certPEM)
		if certBlock == nil {
			return fmt.Errorf("invalid PEM in ca.crt")
		}
		cert, err := x509.ParseCertificate(certBlock.Bytes)
		if err != nil {
			return fmt.Errorf("parse ca cert: %w", err)
		}
		m.caKey = key
		m.caCert = cert
		m.caCertRaw = certPEM
		log.Printf("[MITM] Loaded CA from %s", caDir)
		return nil
	}
	return m.createCA()
}

func (m *Manager) createCA() error {
	if err := os.MkdirAll(caDir, 0755); err != nil {
		return fmt.Errorf("mkdir ca: %w", err)
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("generate ca key: %w", err)
	}

	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "MasterHttpRelayVPN",
			Organization: []string{"MasterHttpRelayVPN"},
		},
		NotBefore:             now,
		NotAfter:              now.Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return fmt.Errorf("create ca cert: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return fmt.Errorf("parse ca cert: %w", err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	if err := os.WriteFile(CAKeyFile, keyPEM, 0600); err != nil {
		return fmt.Errorf("write ca key: %w", err)
	}
	if err := os.WriteFile(CACertFile, certPEM, 0644); err != nil {
		return fmt.Errorf("write ca cert: %w", err)
	}

	m.caKey = key
	m.caCert = cert
	m.caCertRaw = certPEM
	log.Printf("[MITM] Generated new CA certificate: %s", CACertFile)
	log.Printf("[MITM] >>> Install this file in your browser's Trusted Root CAs! <<<")
	return nil
}

// ServerConfig returns a *tls.Config for acting as a TLS server for domain.
func (m *Manager) ServerConfig(domain string) *tls.Config {
	m.mu.Lock()
	if cfg, ok := m.ctxCache[domain]; ok {
		m.mu.Unlock()
		return cfg
	}
	m.mu.Unlock()

	cert, err := m.issueDomainCert(domain)
	if err != nil {
		log.Printf("[MITM] issue cert for %s: %v", domain, err)
		return nil
	}

	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"http/1.1"},
	}

	m.mu.Lock()
	m.ctxCache[domain] = cfg
	m.mu.Unlock()
	return cfg
}

func (m *Manager) issueDomainCert(domain string) (tls.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate key: %w", err)
	}

	now := time.Now()
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: domain},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(365 * 24 * time.Hour),
		DNSNames:     []string{domain},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, m.caCert, &key.PublicKey, m.caKey)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("sign cert: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	// append CA cert so browsers can chain it
	certPEM = append(certPEM, m.caCertRaw...)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	return tls.X509KeyPair(certPEM, keyPEM)
}

// CACertFile returns the path to the CA certificate for installation guidance.
func CACertFilePath() string { return CACertFile }
