package gosigner

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"golang.org/x/crypto/pkcs12"
	pkcs12modern "software.sslmate.com/src/go-pkcs12"
)

// NewSignerFromPFX loads a signer from a PKCS#12 (PFX) file.
func NewSignerFromPFX(pfxPath string, password string) (*Signer, error) {
	pfxData, err := os.ReadFile(pfxPath)
	if err != nil {
		return nil, fmt.Errorf("read pfx file: %w", err)
	}

	key, cert, err := pkcs12.Decode(pfxData, password)
	if err != nil {
		fallbackKey, fallbackCert, caCerts, fallbackErr := pkcs12modern.DecodeChain(pfxData, password)
		if fallbackErr != nil {
			return nil, fmt.Errorf("decode pfx: %w", err)
		}

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
func NewSigner(cfg Config) (*Signer, error) {
	if cfg.Key == nil {
		return nil, fmt.Errorf("private key is required")
	}
	if len(cfg.Chain) == 0 {
		return nil, fmt.Errorf("certificate chain must contain at least one certificate")
	}
	if _, ok := cfg.Key.(*rsa.PrivateKey); !ok {
		return nil, fmt.Errorf("private key must be RSA")
	}

	return &Signer{cfg: cfg}, nil
}
