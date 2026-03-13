package gosigner

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestSignInvisible(t *testing.T) {
	signer, err := NewSignerFromPFX(filepath.Join("testdata", "test.pfx"), "test123")
	if err != nil {
		t.Fatalf("create signer: %v", err)
	}

	inPath := filepath.Join("testdata", "test.pdf")
	inData, err := os.ReadFile(inPath)
	if err != nil {
		t.Fatalf("read input file: %v", err)
	}

	outPath := filepath.Join(t.TempDir(), "signed-invisible.pdf")
	if err := signer.Sign(SignParams{Src: inPath, Dest: outPath}); err != nil {
		t.Fatalf("Sign returned error: %v", err)
	}

	outData, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read output file: %v", err)
	}
	if len(outData) <= len(inData) {
		t.Fatalf("expected output larger than input: out=%d in=%d", len(outData), len(inData))
	}
	if !bytes.Contains(outData, []byte("adbe.pkcs7.detached")) {
		t.Fatal("output missing adbe.pkcs7.detached marker")
	}
	if !bytes.Contains(outData, []byte("ByteRange")) {
		t.Fatal("output missing ByteRange")
	}
}

func TestSignVisible(t *testing.T) {
	signer, err := NewSignerFromPFX(filepath.Join("testdata", "test.pfx"), "test123")
	if err != nil {
		t.Fatalf("create signer: %v", err)
	}

	visible := true
	rect := Rectangle{X1: 50, Y1: 50, X2: 250, Y2: 120}
	outPath := filepath.Join(t.TempDir(), "signed-visible.pdf")

	err = signer.Sign(SignParams{
		Src:     filepath.Join("testdata", "test.pdf"),
		Dest:    outPath,
		Visible: &visible,
		Rect:    &rect,
	})
	if err != nil {
		t.Fatalf("Sign returned error: %v", err)
	}

	outData, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read output file: %v", err)
	}
	if len(outData) == 0 {
		t.Fatal("output file is empty")
	}
}

func TestSignBytes(t *testing.T) {
	signer, err := NewSignerFromPFX(filepath.Join("testdata", "test.pfx"), "test123")
	if err != nil {
		t.Fatalf("create signer: %v", err)
	}

	inData, err := os.ReadFile(filepath.Join("testdata", "test.pdf"))
	if err != nil {
		t.Fatalf("read input file: %v", err)
	}

	outData, err := signer.SignBytes(inData, SignParams{})
	if err != nil {
		t.Fatalf("SignBytes returned error: %v", err)
	}
	if len(outData) <= len(inData) {
		t.Fatalf("expected output larger than input: out=%d in=%d", len(outData), len(inData))
	}
	if !bytes.Contains(outData, []byte("ByteRange")) {
		t.Fatal("output missing ByteRange")
	}
}

func TestSignStream(t *testing.T) {
	signer, err := NewSignerFromPFX(filepath.Join("testdata", "test.pfx"), "test123")
	if err != nil {
		t.Fatalf("create signer: %v", err)
	}

	inData, err := os.ReadFile(filepath.Join("testdata", "test.pdf"))
	if err != nil {
		t.Fatalf("read input file: %v", err)
	}

	src := bytes.NewReader(inData)
	var dst bytes.Buffer

	visible := true
	rect := Rectangle{X1: 50, Y1: 50, X2: 250, Y2: 120}
	err = signer.SignStream(src, &dst, SignParams{
		Visible: &visible,
		Rect:    &rect,
		Reason:  "Testing",
	})
	if err != nil {
		t.Fatalf("SignStream returned error: %v", err)
	}

	outData := dst.Bytes()
	if len(outData) <= len(inData) {
		t.Fatalf("expected output larger than input: out=%d in=%d", len(outData), len(inData))
	}
	if !bytes.Contains(outData, []byte("adbe.pkcs7.detached")) {
		t.Fatal("output missing adbe.pkcs7.detached marker")
	}
	if !bytes.Contains(outData, []byte("ByteRange")) {
		t.Fatal("output missing ByteRange")
	}
	if !bytes.Contains(outData, []byte("Digitally signed by")) {
		t.Fatal("output missing visible signature text")
	}
}

func TestSignStreamToDiscard(t *testing.T) {
	signer, err := NewSignerFromPFX(filepath.Join("testdata", "test.pfx"), "test123")
	if err != nil {
		t.Fatalf("create signer: %v", err)
	}

	inData, err := os.ReadFile(filepath.Join("testdata", "test.pdf"))
	if err != nil {
		t.Fatalf("read input file: %v", err)
	}

	// SignStream works even with io.Discard as dst (fire-and-forget signing
	// for benchmarking or when only the side effect matters).
	src := bytes.NewReader(inData)
	err = signer.SignStream(src, io.Discard, SignParams{})
	if err != nil {
		t.Fatalf("SignStream to Discard returned error: %v", err)
	}
}

func TestSignWithEncryption(t *testing.T) {
	signer, err := NewSignerFromPFX(filepath.Join("testdata", "test.pfx"), "test123")
	if err != nil {
		t.Fatalf("create signer: %v", err)
	}

	outPath := filepath.Join(t.TempDir(), "signed-encrypted.pdf")
	err = signer.Sign(SignParams{
		Src:      filepath.Join("testdata", "test.pdf"),
		Dest:     outPath,
		Password: "secret",
	})
	if err != nil {
		t.Fatalf("Sign with encryption returned error: %v", err)
	}

	outData, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read encrypted output file: %v", err)
	}
	if len(outData) == 0 {
		t.Fatal("encrypted output file is empty")
	}
}
