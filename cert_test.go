package gosigner

import (
	"path/filepath"
	"testing"
)

func TestNewSignerFromPFX(t *testing.T) {
	pfxPath := filepath.Join("testdata", "test.pfx")

	signer, err := NewSignerFromPFX(pfxPath, "test123")
	if err != nil {
		t.Fatalf("NewSignerFromPFX returned error: %v", err)
	}
	if signer == nil {
		t.Fatal("NewSignerFromPFX returned nil signer")
	}
}

func TestNewSignerFromPEM(t *testing.T) {
	certPath := filepath.Join("testdata", "test-cert.pem")
	keyPath := filepath.Join("testdata", "test-key.pem")

	signer, err := NewSignerFromPEM(certPath, keyPath)
	if err != nil {
		t.Fatalf("NewSignerFromPEM returned error: %v", err)
	}
	if signer == nil {
		t.Fatal("NewSignerFromPEM returned nil signer")
	}
}

func TestNewSignerFromPFXBadPassword(t *testing.T) {
	pfxPath := filepath.Join("testdata", "test.pfx")

	if _, err := NewSignerFromPFX(pfxPath, "wrong-password"); err == nil {
		t.Fatal("expected error for bad password, got nil")
	}
}

func TestNewSignerFromPFXMissingFile(t *testing.T) {
	if _, err := NewSignerFromPFX(filepath.Join("testdata", "does-not-exist.pfx"), "test123"); err == nil {
		t.Fatal("expected error for missing PFX file, got nil")
	}
}

func TestNewSignerFromPEMMissingFile(t *testing.T) {
	if _, err := NewSignerFromPEM(filepath.Join("testdata", "missing-cert.pem"), filepath.Join("testdata", "missing-key.pem")); err == nil {
		t.Fatal("expected error for missing PEM files, got nil")
	}
}
