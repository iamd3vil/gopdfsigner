// Package gopdfsigner provides PDF digital signing using PKCS#7 detached signatures.
//
// It appends an incremental update to the original PDF (leaving the original bytes
// untouched) containing the signature dictionary, widget annotation, and optionally
// a visible signature appearance. Three signing paths are provided:
//
//   - Sign: file-to-file convenience method
//   - SignStream: streaming I/O with seekable input (most memory-efficient)
//   - SignBytes: in-memory operation on byte slices (fastest when PDF is already loaded)
//
// All methods are safe for concurrent use.
package gopdfsigner

import (
	"crypto"
	"crypto/x509"
)

// Rectangle defines the position of the visible signature box on a page.
// Coordinates use PDF coordinate system: (0,0) at bottom-left of page.
type Rectangle struct {
	X1, Y1, X2, Y2 float64
}

// Config holds the signer's certificate and default signature metadata.
type Config struct {
	// Certificate and key (required)
	Key   crypto.PrivateKey
	Chain []*x509.Certificate // Chain[0] = signer cert, rest = intermediates

	// Default signature metadata (can be overridden per-document in SignParams)
	Reason   string
	Contact  string
	Location string

	// Default visible signature settings
	Page    int       // 1-indexed page number (default: 1)
	Rect    Rectangle // Signature box coordinates
	Visible bool      // Whether to render a visible signature box
}

// SignParams holds per-document signing parameters.
// Zero values mean "use Config defaults".
type SignParams struct {
	Src  string // Input PDF file path (used by Sign and SignAndEncrypt)
	Dest string // Output PDF file path (used by Sign and SignAndEncrypt)

	// Optional per-document overrides
	Reason   string     // Override Config.Reason
	Contact  string     // Override Config.Contact
	Location string     // Override Config.Location
	Page     int        // Override Config.Page
	Rect     *Rectangle // Override Config.Rect (nil = use default)
	Visible  *bool      // Override Config.Visible (nil = use default)
}

// EncryptParams holds encryption parameters for SignAndEncrypt.
type EncryptParams struct {
	Password string // User and owner password for AES encryption (required)
	AES256   bool   // Use AES-256 instead of AES-128 (default: false)
}

// Signer signs PDF documents with PKCS#7 digital signatures.
type Signer struct {
	cfg Config

	// Pre-computed DER-encoded certificate chain bytes for PKCS#7 signatures.
	// Computed once at creation time to avoid per-call allocation and copying.
	certBytesDER []byte
}
