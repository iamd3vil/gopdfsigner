package gosigner

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestBuildPKCS7Signature(t *testing.T) {
	certPEM, err := os.ReadFile(filepath.Join("testdata", "test-cert.pem"))
	if err != nil {
		t.Fatalf("read cert: %v", err)
	}
	keyPEM, err := os.ReadFile(filepath.Join("testdata", "test-key.pem"))
	if err != nil {
		t.Fatalf("read key: %v", err)
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		t.Fatal("failed to decode cert PEM")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		t.Fatal("failed to decode key PEM")
	}
	pk, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		t.Fatalf("parse key: %v", err)
	}
	rsaKey, ok := pk.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("expected RSA private key, got %T", pk)
	}

	hash := sha256.Sum256([]byte("test"))
	sig, err := buildPKCS7Signature(rsaKey, []*x509.Certificate{cert}, hash[:], time.Now().UTC())
	if err != nil {
		t.Fatalf("buildPKCS7Signature returned error: %v", err)
	}
	if len(sig) == 0 {
		t.Fatal("signature is empty")
	}
	if sig[0] != 0x30 {
		t.Fatalf("expected ASN.1 SEQUENCE (0x30), got 0x%X", sig[0])
	}
}
