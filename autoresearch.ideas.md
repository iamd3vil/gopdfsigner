# Autoresearch Ideas: SignAndEncrypt Performance

## Promising Ideas to Try
- Implement lightweight PDF encryption without pdfcpu (avoid second parse entirely) — biggest potential win but VERY high complexity, requires understanding PDF encryption spec
- Pool the bytes.Buffer used in SignAndEncrypt for signed data (only useful if SignAndEncrypt is called in tight loops)
- Use mmap for reading source files instead of os.ReadFile (OS-dependent, may not help for small files)
- Try to reduce pdfcpu hex string parsing overhead by using binary Contents value instead of hex
- Investigate parallel hashing + RSA signing (unlikely to help since RSA dominates)
- Pre-allocate the result buffer in SignBytes based on input size + estimated increment size

## Completed (from this list)
- Pre-compute CMS SignedData structure parts — done, ~2% gain
- Use pdfcpu ReadContext (skip validation) for encryption — done, significant gain
- DisableConfigDir() — tried, causes performance degradation
- Pre-allocate result buffer — not worth it, single allocation is fast

## Dead Ends
- Replacing fmt.Fprintf with WriteString in buildIncrement — negligible impact
- Using bytes.Buffer instead of temp file alone — no gain, pdfcpu re-parse is bottleneck
- Disabling WriteObjectStream/WriteXRefStream — actually slower
- Skipping validation in parsePDFStructure — breaks page tree access
- Using SignStream instead of SignBytes — much slower due to io.Copy overhead
- bufio.Writer on output — pdfcpu already uses bufio internally
