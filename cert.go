package gopdfsigner

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	// Standard Go PKCS#12 library — works for most PFX files but fails on
	// files using modern digest algorithms (e.g. SHA-256 MAC).
	"golang.org/x/crypto/pkcs12"
	// Fallback PKCS#12 library that supports modern algorithms and also
	// extracts the full CA chain (not just the leaf cert).
	pkcs12modern "software.sslmate.com/src/go-pkcs12"
)

// NewSignerFromPFX loads a signer from a PKCS#12 (PFX) file.
func NewSignerFromPFX(pfxPath string, password string) (*Signer, error) {
	pfxData, err := os.ReadFile(pfxPath)
	if err != nil {
		return nil, fmt.Errorf("read pfx file: %w", err)
	}

	// Try the standard library first. If it fails (e.g. the PFX uses SHA-256 MAC),
	// fall back to go-pkcs12 which also extracts intermediate CA certificates.
	key, cert, err := pkcs12.Decode(pfxData, password)
	if err != nil {
		fallbackKey, fallbackCert, caCerts, fallbackErr := pkcs12modern.DecodeChain(pfxData, password)
		if fallbackErr != nil {
			return nil, fmt.Errorf("decode pfx: %w", err)
		}

		// Build the chain with the leaf cert first, followed by any intermediates.
		chain := make([]*x509.Certificate, 0, 1+len(caCerts))
		chain = append(chain, fallbackCert)
		chain = append(chain, caCerts...)

		return NewSigner(Config{
			Key:   fallbackKey,
			Chain: chain,
		})
	}

	return NewSigner(Config{
		Key:   key,
		Chain: []*x509.Certificate{cert},
	})
}

// NewSignerFromPEM loads a signer from PEM-encoded certificate and key files.
func NewSignerFromPEM(certPath string, keyPath string) (*Signer, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("read certificate file: %w", err)
	}

	// Parse all PEM blocks in the file to build the certificate chain.
	// The file may contain multiple certificates (leaf + intermediates).
	// Non-CERTIFICATE blocks (e.g. comments, other key types) are skipped.
	var chain []*x509.Certificate
	for len(certPEM) > 0 {
		var block *pem.Block
		block, certPEM = pem.Decode(certPEM)
		if block == nil {
			break
		}

		if block.Type != "CERTIFICATE" {
			continue
		}

		cert, parseErr := x509.ParseCertificate(block.Bytes)
		if parseErr != nil {
			return nil, fmt.Errorf("parse certificate: %w", parseErr)
		}
		chain = append(chain, cert)
	}

	if len(chain) == 0 {
		return nil, fmt.Errorf("no certificates found in PEM file")
	}

	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("read key file: %w", err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("failed to decode key PEM block")
	}

	// Try PKCS#8 first (modern format, wraps algorithm identifier + key).
	// Fall back to PKCS#1 (legacy RSA-only format) if PKCS#8 parsing fails.
	key, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		rsaKey, pkcs1Err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
		if pkcs1Err != nil {
			return nil, fmt.Errorf("parse private key (PKCS#8 and PKCS#1 both failed): %v; %v", err, pkcs1Err)
		}
		key = rsaKey
	}

	return NewSigner(Config{
		Key:   key,
		Chain: chain,
	})
}

// NewSigner creates a signer from an already-parsed configuration.
// Currently only RSA private keys are supported; ECDSA/Ed25519 will
// be rejected since PDF PKCS#7 signatures typically use RSA+SHA256.
func NewSigner(cfg Config) (*Signer, error) {
	if cfg.Key == nil {
		return nil, fmt.Errorf("private key is required")
	}
	if len(cfg.Chain) == 0 {
		return nil, fmt.Errorf("certificate chain must contain at least one certificate")
	}
	rsaKey, ok := cfg.Key.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key must be RSA")
	}
	// Pre-compute CRT values for faster RSA signing if not already done.
	rsaKey.Precompute()

	// Pre-compute DER-encoded certificate chain to avoid per-call allocation.
	var totalLen int
	for _, cert := range cfg.Chain {
		if cert != nil {
			totalLen += len(cert.Raw)
		}
	}
	certDER := make([]byte, 0, totalLen)
	for _, cert := range cfg.Chain {
		if cert != nil {
			certDER = append(certDER, cert.Raw...)
		}
	}

	return &Signer{cfg: cfg, certBytesDER: certDER}, nil
}
