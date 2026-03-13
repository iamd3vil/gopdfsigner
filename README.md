# gosigner

A pure Go library for digitally signing and encrypting PDF documents.

Produces PKCS#7 detached signatures (`/adbe.pkcs7.detached`) compatible with
Adobe Acrobat, Poppler, and macOS Preview. Supports optional visible signature
boxes and AES-128 password encryption.

## Installation

```
go get gosigner
```

Requires Go 1.21 or later.

## Usage

### Sign a PDF file

```go
signer, err := gosigner.NewSignerFromPFX("cert.pfx", "password")
if err != nil {
    log.Fatal(err)
}

err = signer.Sign(gosigner.SignParams{
    Src:  "input.pdf",
    Dest: "signed.pdf",
})
```

### Visible signature

```go
visible := true
rect := gosigner.Rectangle{X1: 30, Y1: 720, X2: 280, Y2: 790}

err = signer.Sign(gosigner.SignParams{
    Src:      "input.pdf",
    Dest:     "signed.pdf",
    Visible:  &visible,
    Rect:     &rect,
    Reason:   "Document approval",
    Location: "New York, NY",
    Contact:  "signer@example.com",
})
```

Coordinates use the PDF coordinate system: (0,0) at the bottom-left of the page.
The example above places the signature box near the top-left of a US Letter page.

### Sign and encrypt

```go
err = signer.Sign(gosigner.SignParams{
    Src:      "input.pdf",
    Dest:     "signed-encrypted.pdf",
    Password: "secret",
})
```

This signs first, then applies AES-128 encryption with the given password as
both the user and owner password. Print permission is allowed; all other
permissions are restricted.

### Sign in memory

```go
pdfData, _ := os.ReadFile("input.pdf")
signedData, err := signer.SignBytes(pdfData, gosigner.SignParams{})
```

### Stream signing (low memory)

For large files where holding the entire PDF in memory is undesirable:

```go
src, _ := os.Open("large.pdf")
defer src.Close()
dst, _ := os.Create("signed.pdf")
defer dst.Close()

err = signer.SignStream(src, dst, gosigner.SignParams{})
```

`SignStream` keeps heap usage at roughly 20KB regardless of PDF size. The
source file is read twice (once for parsing, once for hashing and copying)
but never loaded into memory as a whole.

### Load certificates

From a PKCS#12 / PFX file:

```go
signer, err := gosigner.NewSignerFromPFX("cert.pfx", "password")
```

From PEM files:

```go
signer, err := gosigner.NewSignerFromPEM("cert.pem", "key.pem")
```

The PEM loader supports certificate chains: if `cert.pem` contains multiple
certificates, the first is used as the signer certificate and the rest are
included as intermediates.

From an already-parsed key and certificate:

```go
signer, err := gosigner.NewSigner(gosigner.Config{
    Key:   rsaPrivateKey,
    Chain: []*x509.Certificate{signerCert, intermediateCert},
})
```

### Config defaults

Metadata and visibility settings can be set once on the `Config` and
overridden per-document in `SignParams`:

```go
signer, _ := gosigner.NewSigner(gosigner.Config{
    Key:      key,
    Chain:    chain,
    Reason:   "Approved",
    Location: "HQ",
    Visible:  true,
    Rect:     gosigner.Rectangle{X1: 30, Y1: 720, X2: 280, Y2: 790},
})

// Uses Config defaults:
signer.Sign(gosigner.SignParams{Src: "a.pdf", Dest: "a-signed.pdf"})

// Overrides reason for this document:
signer.Sign(gosigner.SignParams{Src: "b.pdf", Dest: "b-signed.pdf", Reason: "Reviewed"})
```

## API

```go
// Constructors
func NewSigner(cfg Config) (*Signer, error)
func NewSignerFromPFX(pfxPath, password string) (*Signer, error)
func NewSignerFromPEM(certPath, keyPath string) (*Signer, error)

// Signing
func (s *Signer) Sign(params SignParams) error
func (s *Signer) SignBytes(pdfData []byte, params SignParams) ([]byte, error)
func (s *Signer) SignStream(src io.ReadSeeker, dst io.Writer, params SignParams) error
```

`Sign` reads from `Src`, writes to `Dest`. If `Dest` is empty, it overwrites `Src`.

`SignBytes` is the fastest path when the PDF is already in memory.

`SignStream` is the most memory-efficient path for large files.

All three methods are safe for concurrent use from multiple goroutines.

## Performance

Benchmarks on an Intel i7-1165G7 (4 cores / 8 threads), visible signing:

### Single-threaded (docs/sec)

| PDF size | SignBytes | SignStream |
|----------|-----------|------------|
| 10 KB    | 624       | 642        |
| 100 KB   | 470       | 636        |
| 500 KB   | 298       | 726        |
| 1 MB     | 212       | 558        |
| 5 MB     | 82        | 120        |

### 8 threads parallel (docs/sec)

| PDF size | SignBytes | SignStream |
|----------|-----------|------------|
| 10 KB    | 3,247     | 871        |
| 100 KB   | 2,849     | 767        |
| 500 KB   | 2,160     | 558        |
| 1 MB     | 1,239     | 564        |
| 5 MB     | 300       | 212        |

### Memory per operation

| PDF size | SignBytes | SignStream |
|----------|----------|------------|
| 10 KB    | 144 KB   | 116 KB     |
| 100 KB   | 330 KB   | 210 KB     |
| 500 KB   | 1,135 KB | 613 KB     |
| 1 MB     | 2,195 KB | 1,147 KB   |
| 5 MB     | 10,386 KB| 5,249 KB   |

Use `SignBytes` when throughput matters and data is already in memory. Use
`SignStream` when working with files to cut heap usage by ~50%.

The fixed overhead is ~1.3ms for RSA-2048 PKCS#1v1.5 signing (the
`buildPKCS7Signature` step). Everything else scales linearly with PDF size.

## How it works

1. The input PDF is parsed with [pdfcpu](https://github.com/pdfcpu/pdfcpu)
   to read the cross-reference table, catalog, and target page dictionary.

2. An incremental update is constructed containing:
   - A signature value dictionary (`/Type /Sig`, `/SubFilter /adbe.pkcs7.detached`)
     with ByteRange and Contents placeholders
   - A widget annotation (`/Subtype /Widget`, `/FT /Sig`) linked to the target page
   - An appearance stream Form XObject (if visible)
   - Modified catalog (with `/AcroForm` and `/SigFlags 3`)
   - Modified page (with the widget added to `/Annots`)
   - Cross-reference table and trailer with `/Prev` pointing to the original xref

3. The ByteRange placeholder is patched with actual byte offsets.

4. The signed byte ranges (everything except the Contents hex string) are
   hashed with SHA-256.

5. A PKCS#7/CMS `SignedData` structure is built using Go's `encoding/asn1`
   and `crypto/rsa` (PKCS#1v1.5 with SHA-256), containing the signer
   certificate, authenticated attributes (content type, message digest,
   signing time), and the RSA signature.

6. The DER-encoded PKCS#7 is hex-encoded and patched into the Contents
   placeholder.

7. If encryption is requested, pdfcpu applies AES-128 encryption as a
   post-processing step on the signed output.

## Limitations

- RSA signatures only (no ECDSA). Matches the PKCS#1v1.5 / SHA-256 profile
  used by most PDF signing implementations.
- Single signature per document. Incremental append for multi-signature is
  not supported.
- No timestamp authority (TSA) integration. Signatures include a local
  signing time but no RFC 3161 timestamp.
- No PDF/A compliance.
- Encryption is AES-128 only (V=4, R=4). AES-256 requires pdfcpu
  configuration changes.
- The visible signature uses Helvetica and a fixed layout. Custom fonts and
  images are not supported.

## Dependencies

| Dependency | Purpose |
|------------|---------|
| `github.com/pdfcpu/pdfcpu` | PDF parsing, object model, AES-128 encryption |
| `golang.org/x/crypto/pkcs12` | PKCS#12 / PFX file decoding |
| `software.sslmate.com/src/go-pkcs12` | Fallback PFX decoder for modern digest algorithms |

Everything else is Go standard library: `crypto/rsa`, `crypto/x509`,
`crypto/sha256`, `encoding/asn1`, `encoding/pem`.

## License

See LICENSE file.
