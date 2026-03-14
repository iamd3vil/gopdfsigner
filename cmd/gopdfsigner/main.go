// Command gopdfsigner signs and optionally encrypts PDF files.
//
// Usage:
//
//	gopdfsigner sign   [flags] -src input.pdf -dest output.pdf
//	gopdfsigner encrypt [flags] -src input.pdf -dest output.pdf
//
// The "sign" subcommand digitally signs a PDF using a PKCS#7 detached signature.
// The "encrypt" subcommand signs and then encrypts with AES.
package main

import (
	"flag"
	"fmt"
	"os"

	gopdfsigner "github.com/iamd3vil/gopdfsigner"
)

const usage = `gopdfsigner — sign and encrypt PDF files

Usage:
  gopdfsigner sign    [flags]   Sign a PDF
  gopdfsigner encrypt [flags]   Sign and encrypt a PDF

Common flags:
  -src string        Input PDF path (required)
  -dest string       Output PDF path (required)
  -pfx string        PKCS#12 (.pfx/.p12) certificate path
  -pfx-pass string   PKCS#12 password
  -cert string       PEM certificate path (alternative to -pfx)
  -key string        PEM private key path (alternative to -pfx)
  -reason string     Signature reason
  -contact string    Signer contact info
  -location string   Signing location

Sign flags:
  -page int          Page for visible signature (default: 1)
  -visible           Render a visible signature box
  -x1, -y1, -x2, -y2 float  Signature box coordinates

Encrypt flags:
  -password string   Encryption password (required for encrypt)
  -aes256            Use AES-256 instead of AES-128
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(1)
	}

	cmd := os.Args[1]
	if cmd == "-h" || cmd == "--help" || cmd == "help" {
		fmt.Print(usage)
		return
	}

	if cmd != "sign" && cmd != "encrypt" {
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n%s", cmd, usage)
		os.Exit(1)
	}

	fs := flag.NewFlagSet(cmd, flag.ExitOnError)

	// Certificate flags
	pfxPath := fs.String("pfx", "", "PKCS#12 (.pfx/.p12) certificate path")
	pfxPass := fs.String("pfx-pass", "", "PKCS#12 password")
	certPath := fs.String("cert", "", "PEM certificate path")
	keyPath := fs.String("key", "", "PEM private key path")

	// I/O flags
	src := fs.String("src", "", "Input PDF path (required)")
	dest := fs.String("dest", "", "Output PDF path (required)")

	// Signature metadata
	reason := fs.String("reason", "", "Signature reason")
	contact := fs.String("contact", "", "Signer contact info")
	location := fs.String("location", "", "Signing location")

	// Visible signature
	page := fs.Int("page", 1, "Page for visible signature")
	visible := fs.Bool("visible", false, "Render a visible signature box")
	x1 := fs.Float64("x1", 0, "Signature box X1")
	y1 := fs.Float64("y1", 0, "Signature box Y1")
	x2 := fs.Float64("x2", 0, "Signature box X2")
	y2 := fs.Float64("y2", 0, "Signature box Y2")

	// Encrypt flags
	password := fs.String("password", "", "Encryption password")
	aes256 := fs.Bool("aes256", false, "Use AES-256 instead of AES-128")

	fs.Parse(os.Args[2:])

	// Validate required flags
	if *src == "" || *dest == "" {
		fatal("-src and -dest are required")
	}

	// Build signer
	signer, err := buildSigner(*pfxPath, *pfxPass, *certPath, *keyPath)
	if err != nil {
		fatal("load certificate: %v", err)
	}

	// Build sign params
	params := gopdfsigner.SignParams{
		Src:      *src,
		Dest:     *dest,
		Reason:   *reason,
		Contact:  *contact,
		Location: *location,
		Page:     *page,
	}
	if *visible {
		v := true
		params.Visible = &v
		rect := gopdfsigner.Rectangle{X1: *x1, Y1: *y1, X2: *x2, Y2: *y2}
		params.Rect = &rect
	}

	switch cmd {
	case "sign":
		if err := signer.Sign(params); err != nil {
			fatal("sign: %v", err)
		}
		fmt.Printf("Signed %s → %s\n", *src, *dest)

	case "encrypt":
		if *password == "" {
			fatal("-password is required for encrypt")
		}
		enc := gopdfsigner.EncryptParams{
			Password: *password,
			AES256:   *aes256,
		}
		if err := signer.SignAndEncrypt(params, enc); err != nil {
			fatal("sign and encrypt: %v", err)
		}
		fmt.Printf("Signed and encrypted %s → %s\n", *src, *dest)
	}
}

func buildSigner(pfxPath, pfxPass, certPath, keyPath string) (*gopdfsigner.Signer, error) {
	if pfxPath != "" {
		return gopdfsigner.NewSignerFromPFX(pfxPath, pfxPass)
	}
	if certPath != "" && keyPath != "" {
		return gopdfsigner.NewSignerFromPEM(certPath, keyPath)
	}
	return nil, fmt.Errorf("provide either -pfx or both -cert and -key")
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", args...)
	os.Exit(1)
}
