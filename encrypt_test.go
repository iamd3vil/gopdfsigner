package gosigner

import (
	"os"
	"path/filepath"
	"testing"
)

func TestEncryptPDF(t *testing.T) {
	inData, err := os.ReadFile(filepath.Join("testdata", "test.pdf"))
	if err != nil {
		t.Fatalf("read input PDF: %v", err)
	}

	dir := t.TempDir()
	inPath := filepath.Join(dir, "input.pdf")
	outPath := filepath.Join(dir, "encrypted.pdf")

	if err := os.WriteFile(inPath, inData, 0o644); err != nil {
		t.Fatalf("write temp input PDF: %v", err)
	}

	if err := encryptPDF(inPath, outPath, "secret"); err != nil {
		t.Fatalf("encryptPDF returned error: %v", err)
	}

	outData, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read encrypted output PDF: %v", err)
	}
	if len(outData) == 0 {
		t.Fatal("encrypted output file is empty")
	}
}
