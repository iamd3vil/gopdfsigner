# gopdfsigner

A pure Go library for digitally signing and encrypting PDF documents.

Produces PKCS#7 detached signatures (`/adbe.pkcs7.detached`) compatible with
Adobe Acrobat, Poppler, and macOS Preview. Supports optional visible signature
boxes and AES password encryption (AES-128 or AES-256).

## Installation

```
go get gopdfsigner
```

Requires Go 1.21 or later.

## Usage

### Sign a PDF file

```go
signer, err := gopdfsigner.NewSignerFromPFX("cert.pfx", "password")
if err != nil {
    log.Fatal(err)
}

err = signer.Sign(gopdfsigner.SignParams{
    Src:  "input.pdf",
    Dest: "signed.pdf",
})
```

### Visible signature

```go
visible := true
rect := gopdfsigner.Rectangle{X1: 30, Y1: 720, X2: 280, Y2: 790}

err = signer.Sign(gopdfsigner.SignParams{
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
err = signer.SignAndEncrypt(
    gopdfsigner.SignParams{
        Src:  "input.pdf",
        Dest: "signed-encrypted.pdf",
    },
    gopdfsigner.EncryptParams{
        Password: "secret",
    },
)
```

This signs first, then applies AES-128 encryption with the given password as
both the user and owner password. Print permission is allowed; all other
permissions are restricted. For AES-256 encryption, set `AES256: true`:

```go
err = signer.SignAndEncrypt(
    gopdfsigner.SignParams{
        Src:  "input.pdf",
        Dest: "signed-encrypted.pdf",
    },
    gopdfsigner.EncryptParams{
        Password: "secret",
        AES256:   true,
    },
)
```

Encryption is only available via `SignAndEncrypt`. The `Sign`, `SignBytes`, and
`SignStream` methods do not accept encryption parameters.

### Sign in memory

```go
pdfData, _ := os.ReadFile("input.pdf")
signedData, err := signer.SignBytes(pdfData, gopdfsigner.SignParams{})
```

### Stream signing (low memory)

For large files where holding the entire PDF in memory is undesirable:

```go
src, _ := os.Open("large.pdf")
defer src.Close()
dst, _ := os.Create("signed.pdf")
defer dst.Close()

err = signer.SignStream(src, dst, gopdfsigner.SignParams{})
```

`SignStream` keeps heap usage at roughly 20KB regardless of PDF size. The
source file is read twice (once for parsing, once for hashing and copying)
but never loaded into memory as a whole.

### Load certificates

From a PKCS#12 / PFX file:

```go
signer, err := gopdfsigner.NewSignerFromPFX("cert.pfx", "password")
```

From PEM files:

```go
signer, err := gopdfsigner.NewSignerFromPEM("cert.pem", "key.pem")
```

The PEM loader supports certificate chains: if `cert.pem` contains multiple
certificates, the first is used as the signer certificate and the rest are
included as intermediates.

From an already-parsed key and certificate:

```go
signer, err := gopdfsigner.NewSigner(gopdfsigner.Config{
    Key:   rsaPrivateKey,
    Chain: []*x509.Certificate{signerCert, intermediateCert},
})
```

### Config defaults

Metadata and visibility settings can be set once on the `Config` and
overridden per-document in `SignParams`:

```go
signer, _ := gopdfsigner.NewSigner(gopdfsigner.Config{
    Key:      key,
    Chain:    chain,
    Reason:   "Approved",
    Location: "HQ",
    Visible:  true,
    Rect:     gopdfsigner.Rectangle{X1: 30, Y1: 720, X2: 280, Y2: 790},
})

// Uses Config defaults:
signer.Sign(gopdfsigner.SignParams{Src: "a.pdf", Dest: "a-signed.pdf"})

// Overrides reason for this document:
signer.Sign(gopdfsigner.SignParams{Src: "b.pdf", Dest: "b-signed.pdf", Reason: "Reviewed"})
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

// Signing + encryption
func (s *Signer) SignAndEncrypt(params SignParams, enc EncryptParams) error
```

`Sign` reads from `Src`, writes to `Dest`. If `Dest` is empty, it overwrites `Src`.

`SignBytes` is the fastest path when the PDF is already in memory.

`SignStream` is the most memory-efficient path for large files.

`SignAndEncrypt` signs to a temp file, then encrypts to `Dest` using pdfcpu.

All methods are safe for concurrent use from multiple goroutines.

## Performance

All benchmarks use visible signing. Docs/sec = 1,000,000,000 ÷ ns/op.

### Machines tested

| Machine | CPU | Cores / Threads | OS |
|---------|-----|----------------:|-----|
| Laptop  | Intel i7-1165G7 | 4 / 8 | Linux |
| Mac     | Apple M3 Pro | 11 | macOS |
| Server  | AMD Ryzen 7 9700X | 8 / 16 | Linux |

### Single-threaded — SignBytes (docs/sec)

| PDF size | i7-1165G7 | M3 Pro | Ryzen 9700X |
|----------|----------:|-------:|------------:|
| 10 KB    | 624       | 1,158  | 1,754       |
| 100 KB   | 470       | 1,115  | 1,614       |
| 500 KB   | 298       | 957    | 1,205       |
| 1 MB     | 212       | 804    | 882         |
| 5 MB     | 82        | 354    | 316         |

### Single-threaded — SignStream (docs/sec)

| PDF size | i7-1165G7 | M3 Pro | Ryzen 9700X |
|----------|----------:|-------:|------------:|
| 10 KB    | 642       | 1,152  | 1,740       |
| 100 KB   | 636       | 1,113  | 1,617       |
| 500 KB   | 726       | 962    | 1,252       |
| 1 MB     | 558       | 817    | 935         |
| 5 MB     | 120       | 371    | 342         |

### Parallel — SignBytes (docs/sec)

| PDF size | i7-1165G7 (8T) | M3 Pro (11T) | Ryzen 9700X (16T) |
|----------|---------------:|-------------:|-------------------:|
| 10 KB    | 3,247          | 7,418        | 13,350             |
| 100 KB   | 2,849          | 6,550        | 12,039             |
| 500 KB   | 2,160          | 5,116        | 8,690              |
| 1 MB     | 1,239          | 4,260        | 5,812              |
| 5 MB     | 300            | 2,087        | 1,147              |

### Parallel — SignStream (docs/sec)

| PDF size | i7-1165G7 (8T) | M3 Pro (11T) | Ryzen 9700X (16T) |
|----------|---------------:|-------------:|-------------------:|
| 10 KB    | 871            | 7,634        | 13,477             |
| 100 KB   | 767            | 6,938        | 12,389             |
| 500 KB   | 558            | 5,352        | 9,621              |
| 1 MB     | 564            | 4,270        | 7,193              |
| 5 MB     | 212            | 1,982        | 2,241              |

### Memory per operation

| PDF size | SignBytes | SignStream |
|----------|----------|------------|
| 10 KB    | 103 KB   | 87 KB      |
| 100 KB   | 293 KB   | 181 KB     |
| 500 KB   | 1,096 KB | 583 KB     |
| 1 MB     | 2,142 KB | 1,112 KB   |
| 5 MB     | 10,332 KB| 5,200 KB   |

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

7. If encryption is requested, pdfcpu applies AES encryption (128-bit or
   256-bit) as a post-processing step on the signed output.

## Limitations

- RSA signatures only (no ECDSA). Matches the PKCS#1v1.5 / SHA-256 profile
  used by most PDF signing implementations.
- Single signature per document. Incremental append for multi-signature is
  not supported.
- No timestamp authority (TSA) integration. Signatures include a local
  signing time but no RFC 3161 timestamp.
- No PDF/A compliance.
- Encryption supports AES-128 (default) and AES-256. No RC4 support.
- The visible signature uses Helvetica and a fixed layout. Custom fonts and
  images are not supported.

## Dependencies

| Dependency | Purpose |
|------------|---------|
| `github.com/pdfcpu/pdfcpu` | PDF parsing, object model, AES encryption |
| `golang.org/x/crypto/pkcs12` | PKCS#12 / PFX file decoding |
| `software.sslmate.com/src/go-pkcs12` | Fallback PFX decoder for modern digest algorithms |

Everything else is Go standard library: `crypto/rsa`, `crypto/x509`,
`crypto/sha256`, `encoding/asn1`, `encoding/pem`.

## License

See LICENSE file.
