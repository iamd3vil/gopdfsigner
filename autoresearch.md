# Autoresearch: SignAndEncrypt Performance

## Objective
Optimize the `SignAndEncrypt` method in gopdfsigner, which signs a PDF and then encrypts it with AES.

## Metrics
- **Primary**: ns_per_op (nanoseconds, lower is better) — wall-clock time for SignAndEncrypt on a 100KB PDF
- **Secondary**: allocs_per_op, bytes_per_op — memory pressure indicators

## Current State
- **Baseline**: 1,844,526 ns/op, 1,961 allocs, 1,074,419 bytes/op
- **Current**: ~1,421,000 ns/op, 1,706 allocs, 982,798 bytes/op
- **Improvement**: ~23% faster, 13% fewer allocs, 8.5% less memory

## How to Run
`./autoresearch.sh` — runs `BenchmarkSignAndEncrypt/100KB` with count=5, outputs `METRIC name=number` lines.

## Files in Scope
- `signer.go` — Core signing logic. Contains `SignAndEncrypt`, `SignStream`, `SignBytes`, `parsePDFStructure`, `buildIncrement`, buffer pools, `encodeUpperHex`, `formatByteRange`.
- `encrypt.go` — `encryptPDF`, `encryptPDFStream`, `newEncryptConf` wrappers around pdfcpu encryption.
- `signature.go` — PKCS#7/CMS signature building (`buildPKCS7Signature`). Pre-computed constants at init.
- `config.go` — Types: `Signer` (with `certBytesDER`), `Config`, `SignParams`, `EncryptParams`, `Rectangle`.
- `appearance.go` — Visible signature appearance stream builder, `pdfStringReplacer`.
- `cert.go` — Certificate loading with `rsaKey.Precompute()`.
- `bench_test.go` — Benchmarks including `BenchmarkSignAndEncrypt`.

## Off Limits
- `testdata/` — Test fixtures, do not modify.
- `cmd/` — CLI tool, not performance-critical.
- `go.mod` / `go.sum` — No new dependencies allowed.
- Do NOT change the public API signatures.

## Constraints
- All tests must pass (`go test ./... -count=1`).
- No new external dependencies.
- Public API must remain backward-compatible.

## Profile Breakdown (final state)
| Component | CPU % |
|-----------|-------|
| RSA SignPKCS1v15 | ~58% (immovable) |
| pdfcpu ReadContext | ~13% (external) |
| pdfcpu WriteContext | ~12% (external) |
| parsePDFStructure | ~6% (includes pdfcpu ReadAndValidate) |
| buildIncrement + hashing | ~4% |
| Other (alloc, IO) | ~7% |

## What's Been Tried

### Wins (kept, cumulative ~23% improvement)
1. **SignBytes + in-memory encryption** (1.5%): Replaced file-based pipeline with ReadFile→SignBytes→api.Encrypt from memory. Eliminates temp file.
2. **Disable pdfcpu optimization** (3.5%): Set Optimize/OptimizeBeforeWriting/OptimizeResourceDicts=false for encryption.
3. **Reduce contentsPlaceholderLen** (17%): 16384→3072 hex chars. Actual sig uses ~2800 chars. Smaller = less for pdfcpu to parse.
4. **Pre-compute CMS constants** (19.7%): contentTypeAttr, digestAlgorithm DER, algorithm IDs at init.
5. **Pre-compute certBytesDER** (19.9%): Certificate chain DER bytes at Signer creation.
6. **Skip validation in encryption** (22.0%): Use ReadContext instead of ReadAndValidate for encryption.
7. **Pre-build pdfStringReplacer** (20.9%): Package-level replacer instead of per-call.
8. **Direct hex encoding** (22.7%): Encode directly into target buffer, custom uppercase hex encoder.
9. **Direct ByteRange formatting** (22.1%): formatByteRange writes directly to buffer, no fmt.Sprintf.
10. **RSA Precompute** (22.9%): Ensure CRT values computed for faster signing.

### Dead Ends (discarded)
- In-memory buffer alone (no SignBytes): Bottleneck is pdfcpu parse, not file I/O
- Replace fmt.Fprintf in buildIncrement: Negligible — buffer is ~20KB
- Disable WriteObjectStream/WriteXRefStream: Actually slower
- api.DisableConfigDir() in init(): Performance degradation
- Skip validation in parsePDFStructure: Breaks page tree access
- SignStream instead of SignBytes: Much slower due to io.Copy
- bufio.Writer on output: pdfcpu already uses bufio internally
