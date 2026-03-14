package gopdfsigner

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pdfcpu/pdfcpu/pkg/api"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/model"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/types"
)

const (
	contentsPlaceholderLen = 16384 // Hex chars for 8192 bytes.
	byteRangePlaceholder   = "/ByteRange [0 0000000000 0000000000 0000000000]"
)

// Pre-computed zeros placeholder (avoids strings.Repeat allocation per call).
var contentsZeros = strings.Repeat("0", contentsPlaceholderLen)

var bufPool = sync.Pool{
	New: func() any {
		b := new(bytes.Buffer)
		b.Grow(32 * 1024)
		return b
	},
}

var hashPool = sync.Pool{
	New: func() any {
		return sha256.New()
	},
}

var hexBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, contentsPlaceholderLen)
		return &b
	},
}

func (s *Signer) resolveParams(params SignParams) (reason, contact, location string, page int, rect Rectangle, visible bool) {
	reason = s.cfg.Reason
	if params.Reason != "" {
		reason = params.Reason
	}
	contact = s.cfg.Contact
	if params.Contact != "" {
		contact = params.Contact
	}
	location = s.cfg.Location
	if params.Location != "" {
		location = params.Location
	}
	page = s.cfg.Page
	if params.Page > 0 {
		page = params.Page
	}
	if page < 1 {
		page = 1
	}
	rect = s.cfg.Rect
	if params.Rect != nil {
		rect = *params.Rect
	}
	visible = s.cfg.Visible
	if params.Visible != nil {
		visible = *params.Visible
	}
	return
}

func (s *Signer) signerName() string {
	if len(s.cfg.Chain) > 0 && s.cfg.Chain[0] != nil {
		cert := s.cfg.Chain[0]
		if cert.Subject.CommonName != "" {
			return cert.Subject.CommonName
		}
		if len(cert.Subject.Organization) > 0 {
			return cert.Subject.Organization[0]
		}
		return cert.SerialNumber.String()
	}
	return ""
}

// findStartxrefFromReader reads the last 1024 bytes of src to find the startxref offset.
func findStartxrefFromReader(src io.ReadSeeker, srcSize int64) (int64, error) {
	readSize := int64(1024)
	if readSize > srcSize {
		readSize = srcSize
	}
	if _, err := src.Seek(-readSize, io.SeekEnd); err != nil {
		return 0, fmt.Errorf("seek to tail: %w", err)
	}
	tail := make([]byte, readSize)
	if _, err := io.ReadFull(src, tail); err != nil {
		return 0, fmt.Errorf("read tail: %w", err)
	}
	return findStartxrefOffset(tail)
}

func findStartxrefOffset(data []byte) (int64, error) {
	idx := bytes.LastIndex(data, []byte("startxref"))
	if idx == -1 {
		return 0, fmt.Errorf("startxref not found")
	}
	rest := data[idx+len("startxref"):]
	i := 0
	for i < len(rest) && (rest[i] == ' ' || rest[i] == '\n' || rest[i] == '\r' || rest[i] == '\t') {
		i++
	}
	j := i
	for j < len(rest) && rest[j] >= '0' && rest[j] <= '9' {
		j++
	}
	if j == i {
		return 0, fmt.Errorf("no offset after startxref")
	}
	offset, err := strconv.ParseInt(string(rest[i:j]), 10, 64)
	if err != nil {
		return 0, err
	}
	return offset, nil
}

func serializeObject(obj types.Object) string {
	if obj == nil {
		return "null"
	}
	if s, ok := obj.(interface{ PDFString() string }); ok {
		return s.PDFString()
	}
	return fmt.Sprintf("%v", obj)
}

func getPageInfo(ctx *model.Context, pageNum int) (types.IndirectRef, types.Dict, error) {
	rootObj, err := ctx.Dereference(*ctx.Root)
	if err != nil {
		return types.IndirectRef{}, nil, fmt.Errorf("dereference root: %w", err)
	}
	rootDict, ok := rootObj.(types.Dict)
	if !ok {
		return types.IndirectRef{}, nil, fmt.Errorf("root is not a dict")
	}
	pagesRef := rootDict.IndirectRefEntry("Pages")
	if pagesRef == nil {
		return types.IndirectRef{}, nil, fmt.Errorf("no Pages in root")
	}
	return resolvePageRef(ctx, *pagesRef, pageNum)
}

func resolvePageRef(ctx *model.Context, nodeRef types.IndirectRef, targetPage int) (types.IndirectRef, types.Dict, error) {
	obj, err := ctx.Dereference(nodeRef)
	if err != nil {
		return types.IndirectRef{}, nil, err
	}
	dict, ok := obj.(types.Dict)
	if !ok {
		return types.IndirectRef{}, nil, fmt.Errorf("node is not a dict")
	}
	typeName := ""
	if t := dict.NameEntry("Type"); t != nil {
		typeName = *t
	}
	if typeName == "Page" {
		if targetPage == 1 {
			return nodeRef, dict, nil
		}
		return types.IndirectRef{}, nil, fmt.Errorf("page not found")
	}
	kids := dict.ArrayEntry("Kids")
	if kids == nil {
		return types.IndirectRef{}, nil, fmt.Errorf("no Kids in Pages node")
	}
	currentPage := 0
	for _, kid := range kids {
		kidRef, ok := kid.(types.IndirectRef)
		if !ok {
			continue
		}
		kidObj, err := ctx.Dereference(kidRef)
		if err != nil {
			continue
		}
		kidDict, ok := kidObj.(types.Dict)
		if !ok {
			continue
		}
		kidType := ""
		if t := kidDict.NameEntry("Type"); t != nil {
			kidType = *t
		}
		count := 0
		if kidType == "Page" {
			count = 1
		} else if c := kidDict.IntEntry("Count"); c != nil {
			count = *c
		}
		if currentPage+count >= targetPage {
			return resolvePageRef(ctx, kidRef, targetPage-currentPage)
		}
		currentPage += count
	}
	return types.IndirectRef{}, nil, fmt.Errorf("page %d not found", targetPage)
}

// pdfStructure holds the PDF metadata extracted from parsing, needed to build
// the incremental update.
type pdfStructure struct {
	nextObjNr      int
	prevXrefOffset int64
	catalogObjNr   int
	catalogDict    types.Dict
	pageObjNr      int
	pageDict       types.Dict
	infoRef        *types.IndirectRef
	idArray        types.Array
}

// parsePDFStructure reads the minimal structure needed for signing from src.
func parsePDFStructure(src io.ReadSeeker, page int) (*pdfStructure, error) {
	srcSize, err := src.Seek(0, io.SeekEnd)
	if err != nil {
		return nil, fmt.Errorf("seek end: %w", err)
	}

	prevXrefOffset, err := findStartxrefFromReader(src, srcSize)
	if err != nil {
		return nil, fmt.Errorf("find startxref: %w", err)
	}

	if _, err := src.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("seek start: %w", err)
	}
	conf := model.NewDefaultConfiguration()
	ctx, err := api.ReadAndValidate(src, conf)
	if err != nil {
		return nil, fmt.Errorf("parse PDF: %w", err)
	}

	catalogObjNr := int(ctx.Root.ObjectNumber)
	rootObj, err := ctx.Dereference(*ctx.Root)
	if err != nil {
		return nil, fmt.Errorf("dereference catalog: %w", err)
	}
	catalogDict, ok := rootObj.(types.Dict)
	if !ok {
		return nil, fmt.Errorf("catalog is not a dict")
	}

	pageRef, pageDict, err := getPageInfo(ctx, page)
	if err != nil {
		return nil, fmt.Errorf("get page %d: %w", page, err)
	}

	// Resolve any indirect AcroForm reference while we still have ctx
	if ref := catalogDict.IndirectRefEntry("AcroForm"); ref != nil {
		if o, derr := ctx.Dereference(*ref); derr == nil {
			if d, ok := o.(types.Dict); ok {
				catalogDict["AcroForm"] = d
			}
		}
	}
	// Resolve any indirect Annots reference on the page
	if ref := pageDict.IndirectRefEntry("Annots"); ref != nil {
		if o, derr := ctx.Dereference(*ref); derr == nil {
			if arr, ok := o.(types.Array); ok {
				pageDict["Annots"] = arr
			}
		}
	}

	ps := &pdfStructure{
		nextObjNr:      *ctx.Size,
		prevXrefOffset: prevXrefOffset,
		catalogObjNr:   catalogObjNr,
		catalogDict:    catalogDict,
		pageObjNr:      int(pageRef.ObjectNumber),
		pageDict:       pageDict,
		infoRef:        ctx.Info,
		idArray:        ctx.ID,
	}
	return ps, nil
}

// buildIncrement builds the incremental update buffer and returns it along with
// the byte-range-relative offsets within the increment for ByteRange placeholder,
// Contents hex start/end (all relative to start of incr, not absolute).
type incrOffsets struct {
	byteRangeInIncr    int // offset of ByteRange placeholder within incr
	contentsHexInIncr  int // offset of first hex char of Contents within incr
	contentsHexEndIncr int // offset past last hex char of Contents within incr
}

func (s *Signer) buildIncrement(ps *pdfStructure, srcSize int64, reason, contact, location string, rect Rectangle, visible bool, signingTime time.Time) (*bytes.Buffer, *incrOffsets, error) {
	signerName := s.signerName()

	sigValueObjNr := ps.nextObjNr
	widgetObjNr := ps.nextObjNr + 1
	nextObj := ps.nextObjNr + 2
	appearanceObjNr := 0
	fontObjNr := 0
	if visible {
		appearanceObjNr = nextObj
		nextObj++
		fontObjNr = nextObj
		nextObj++
	}

	incr := bufPool.Get().(*bytes.Buffer)
	incr.Reset()
	incr.WriteByte('\n')

	xrefEntries := map[int]int64{}
	baseOffset := srcSize
	recordOffset := func(objNr int) {
		xrefEntries[objNr] = baseOffset + int64(incr.Len())
	}

	offsets := &incrOffsets{}

	// === Signature Value Dictionary ===
	recordOffset(sigValueObjNr)
	fmt.Fprintf(incr, "%d 0 obj\n", sigValueObjNr)
	fmt.Fprintf(incr, "<<\n")
	fmt.Fprintf(incr, "/Type /Sig\n")
	fmt.Fprintf(incr, "/Filter /Adobe.PPKLite\n")
	fmt.Fprintf(incr, "/SubFilter /adbe.pkcs7.detached\n")
	offsets.byteRangeInIncr = incr.Len()
	fmt.Fprintf(incr, "%s\n", byteRangePlaceholder)
	fmt.Fprintf(incr, "/Contents <")
	offsets.contentsHexInIncr = incr.Len()
	incr.WriteString(contentsZeros)
	offsets.contentsHexEndIncr = incr.Len()
	fmt.Fprintf(incr, ">\n")
	if signerName != "" {
		fmt.Fprintf(incr, "/Name (%s)\n", pdfEscapeString(signerName))
	}
	if reason != "" {
		fmt.Fprintf(incr, "/Reason (%s)\n", pdfEscapeString(reason))
	}
	if contact != "" {
		fmt.Fprintf(incr, "/ContactInfo (%s)\n", pdfEscapeString(contact))
	}
	if location != "" {
		fmt.Fprintf(incr, "/Location (%s)\n", pdfEscapeString(location))
	}
	fmt.Fprintf(incr, "/M (%s)\n", signingTime.Format("D:20060102150405+00'00'"))
	fmt.Fprintf(incr, ">>\n")
	fmt.Fprintf(incr, "endobj\n\n")

	// === Widget Annotation ===
	recordOffset(widgetObjNr)
	fmt.Fprintf(incr, "%d 0 obj\n", widgetObjNr)
	fmt.Fprintf(incr, "<<\n")
	fmt.Fprintf(incr, "/Type /Annot\n")
	fmt.Fprintf(incr, "/Subtype /Widget\n")
	fmt.Fprintf(incr, "/FT /Sig\n")
	fmt.Fprintf(incr, "/T (Signature1)\n")
	fmt.Fprintf(incr, "/V %d 0 R\n", sigValueObjNr)
	fmt.Fprintf(incr, "/F 132\n")
	fmt.Fprintf(incr, "/P %d 0 R\n", ps.pageObjNr)
	if visible && rect.X1 != rect.X2 && rect.Y1 != rect.Y2 {
		fmt.Fprintf(incr, "/Rect [%g %g %g %g]\n", rect.X1, rect.Y1, rect.X2, rect.Y2)
		if appearanceObjNr > 0 {
			fmt.Fprintf(incr, "/AP << /N %d 0 R >>\n", appearanceObjNr)
		}
	} else {
		fmt.Fprintf(incr, "/Rect [0 0 0 0]\n")
	}
	fmt.Fprintf(incr, ">>\n")
	fmt.Fprintf(incr, "endobj\n\n")

	// === Appearance Stream (if visible) ===
	if visible && appearanceObjNr > 0 {
		streamContent := buildAppearanceStream(rect, signerName, reason, location, signingTime)
		width := rect.X2 - rect.X1
		height := rect.Y2 - rect.Y1

		// Font object (separate indirect object for reliable cross-viewer rendering).
		recordOffset(fontObjNr)
		fmt.Fprintf(incr, "%d 0 obj\n", fontObjNr)
		fmt.Fprintf(incr, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>\n")
		fmt.Fprintf(incr, "endobj\n\n")

		// Form XObject.
		recordOffset(appearanceObjNr)
		fmt.Fprintf(incr, "%d 0 obj\n", appearanceObjNr)
		fmt.Fprintf(incr, "<<\n")
		fmt.Fprintf(incr, "/Type /XObject\n")
		fmt.Fprintf(incr, "/Subtype /Form\n")
		fmt.Fprintf(incr, "/FormType 1\n")
		fmt.Fprintf(incr, "/BBox [0 0 %g %g]\n", width, height)
		fmt.Fprintf(incr, "/Resources << /Font << /F1 %d 0 R >> >>\n", fontObjNr)
		fmt.Fprintf(incr, "/Length %d\n", len(streamContent))
		fmt.Fprintf(incr, ">>\n")
		fmt.Fprintf(incr, "stream\n")
		incr.Write(streamContent)
		fmt.Fprintf(incr, "\nendstream\n")
		fmt.Fprintf(incr, "endobj\n\n")
	}

	// === Modified Catalog ===
	recordOffset(ps.catalogObjNr)
	fmt.Fprintf(incr, "%d 0 obj\n", ps.catalogObjNr)
	fmt.Fprintf(incr, "<<\n")
	for key, val := range ps.catalogDict {
		if key == "AcroForm" {
			continue
		}
		fmt.Fprintf(incr, "/%s %s\n", key, serializeObject(val))
	}
	existingFields := ""
	if d := ps.catalogDict.DictEntry("AcroForm"); d != nil {
		if fa := d.ArrayEntry("Fields"); fa != nil {
			for _, f := range fa {
				existingFields += " " + serializeObject(f)
			}
		}
	}
	fmt.Fprintf(incr, "/AcroForm << /Fields [%s %d 0 R] /SigFlags 3 >>\n", existingFields, widgetObjNr)
	fmt.Fprintf(incr, ">>\n")
	fmt.Fprintf(incr, "endobj\n\n")

	// === Modified Page ===
	recordOffset(ps.pageObjNr)
	fmt.Fprintf(incr, "%d 0 obj\n", ps.pageObjNr)
	fmt.Fprintf(incr, "<<\n")
	for key, val := range ps.pageDict {
		if key == "Annots" {
			continue
		}
		fmt.Fprintf(incr, "/%s %s\n", key, serializeObject(val))
	}
	existingAnnots := ""
	if annots := ps.pageDict.ArrayEntry("Annots"); annots != nil {
		for _, a := range annots {
			existingAnnots += " " + serializeObject(a)
		}
	}
	fmt.Fprintf(incr, "/Annots [%s %d 0 R]\n", existingAnnots, widgetObjNr)
	fmt.Fprintf(incr, ">>\n")
	fmt.Fprintf(incr, "endobj\n\n")

	// === Cross-reference table ===
	xrefOffset := baseOffset + int64(incr.Len())
	fmt.Fprintf(incr, "xref\n")
	objNrs := make([]int, 0, len(xrefEntries))
	for nr := range xrefEntries {
		objNrs = append(objNrs, nr)
	}
	sort.Ints(objNrs)
	for _, nr := range objNrs {
		fmt.Fprintf(incr, "%d 1\n", nr)
		fmt.Fprintf(incr, "%010d 00000 n \r\n", xrefEntries[nr])
	}

	// === Trailer ===
	fmt.Fprintf(incr, "trailer\n")
	fmt.Fprintf(incr, "<<\n")
	fmt.Fprintf(incr, "/Size %d\n", nextObj)
	fmt.Fprintf(incr, "/Root %d 0 R\n", ps.catalogObjNr)
	if ps.infoRef != nil {
		fmt.Fprintf(incr, "/Info %d 0 R\n", int(ps.infoRef.ObjectNumber))
	}
	if ps.idArray != nil && len(ps.idArray) > 0 {
		fmt.Fprintf(incr, "/ID %s\n", ps.idArray.PDFString())
	}
	fmt.Fprintf(incr, "/Prev %d\n", ps.prevXrefOffset)
	fmt.Fprintf(incr, ">>\n")
	fmt.Fprintf(incr, "startxref\n")
	fmt.Fprintf(incr, "%d\n", xrefOffset)
	fmt.Fprintf(incr, "%%%%EOF\n")

	return incr, offsets, nil
}

// SignStream signs a PDF by reading from src and writing the signed PDF to dst.
// src must be seekable for PDF parsing and hashing. dst only needs Write.
// This is the most memory-efficient signing method — heap usage is ~20KB for the
// incremental update regardless of PDF size.
func (s *Signer) SignStream(src io.ReadSeeker, dst io.Writer, params SignParams) error {
	reason, contact, location, page, rect, visible := s.resolveParams(params)
	signingTime := time.Now().UTC()

	// Get source size.
	srcSize, err := src.Seek(0, io.SeekEnd)
	if err != nil {
		return fmt.Errorf("seek end: %w", err)
	}

	// Parse PDF structure (xref, catalog, page).
	ps, err := parsePDFStructure(src, page)
	if err != nil {
		return err
	}

	// Build the incremental update buffer (~20KB).
	incr, offsets, err := s.buildIncrement(ps, srcSize, reason, contact, location, rect, visible, signingTime)
	defer bufPool.Put(incr)
	if err != nil {
		return err
	}

	incrBytes := incr.Bytes()

	// Compute absolute positions for ByteRange.
	// The Contents placeholder '<' is at absolute position srcSize + contentsHexInIncr - 1
	// (the -1 accounts for the '<' before the hex digits).
	contentValueStart := srcSize + int64(offsets.contentsHexInIncr) - 1 // position of '<'
	contentValueEnd := srcSize + int64(offsets.contentsHexEndIncr) + 1  // position after '>'
	totalLen := srcSize + int64(len(incrBytes))

	// Patch ByteRange in the increment buffer.
	byteRange := fmt.Sprintf("/ByteRange [0 %010d %010d %010d]",
		contentValueStart,
		contentValueEnd,
		totalLen-contentValueEnd,
	)
	if len(byteRange) != len(byteRangePlaceholder) {
		return fmt.Errorf("ByteRange length mismatch: got %d, want %d", len(byteRange), len(byteRangePlaceholder))
	}
	copy(incrBytes[offsets.byteRangeInIncr:], []byte(byteRange))

	// Hash the signed byte ranges: [0, contentValueStart) and [contentValueEnd, totalLen).
	// The first range is: all of src + incr[0 : contentsHexInIncr-1]
	// The second range is: incr[contentsHexEndIncr+1 :]
	// This avoids allocating a combined buffer.
	contentsIncrStart := offsets.contentsHexInIncr - 1 // offset of '<' within incr
	contentsIncrEnd := offsets.contentsHexEndIncr + 1  // offset after '>' within incr

	h := hashPool.Get().(hash.Hash)
	h.Reset()

	// Hash first range: all of src.
	if _, err := src.Seek(0, io.SeekStart); err != nil {
		hashPool.Put(h)
		return fmt.Errorf("seek start for hash: %w", err)
	}
	if _, err := io.Copy(h, src); err != nil {
		hashPool.Put(h)
		return fmt.Errorf("hash src: %w", err)
	}
	// Hash first range continued: incr bytes before '<'.
	h.Write(incrBytes[:contentsIncrStart])
	// Hash second range: incr bytes after '>'.
	h.Write(incrBytes[contentsIncrEnd:])

	contentHash := h.Sum(nil)
	hashPool.Put(h)

	// Build PKCS#7 signature.
	rsaKey, ok := s.cfg.Key.(*rsa.PrivateKey)
	if !ok {
		return fmt.Errorf("private key must be RSA")
	}
	pkcs7Sig, err := buildPKCS7Signature(rsaKey, s.cfg.Chain, contentHash, signingTime)
	if err != nil {
		return fmt.Errorf("build PKCS#7 signature: %w", err)
	}

	// Hex-encode signature and patch Contents in the increment buffer.
	sigHexLen := hex.EncodedLen(len(pkcs7Sig))
	if sigHexLen > contentsPlaceholderLen {
		return fmt.Errorf("PKCS#7 signature too large: %d hex chars (max %d)", sigHexLen, contentsPlaceholderLen)
	}
	hexBuf := hexBufPool.Get().(*[]byte)
	for i := range *hexBuf {
		(*hexBuf)[i] = '0'
	}
	hex.Encode(*hexBuf, pkcs7Sig)
	for i := 0; i < sigHexLen; i++ {
		c := (*hexBuf)[i]
		if c >= 'a' && c <= 'f' {
			(*hexBuf)[i] = c - 32
		}
	}
	copy(incrBytes[offsets.contentsHexInIncr:offsets.contentsHexEndIncr], *hexBuf)
	hexBufPool.Put(hexBuf)

	// Write to dst: original PDF + patched increment.
	if _, err := src.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("seek start for write: %w", err)
	}
	if _, err := io.Copy(dst, src); err != nil {
		return fmt.Errorf("write src to dst: %w", err)
	}
	if _, err := dst.Write(incrBytes); err != nil {
		return fmt.Errorf("write increment to dst: %w", err)
	}

	return nil
}

// Sign signs a PDF file and writes the result to the destination path.
func (s *Signer) Sign(params SignParams) error {
	srcFile, err := os.Open(params.Src)
	if err != nil {
		return fmt.Errorf("open input PDF: %w", err)
	}
	defer srcFile.Close()

	destPath := params.Dest
	if destPath == "" {
		destPath = params.Src
	}

	dstFile, err := os.Create(destPath)
	if err != nil {
		return fmt.Errorf("create output PDF: %w", err)
	}
	defer dstFile.Close()

	if err := s.SignStream(srcFile, dstFile, params); err != nil {
		return fmt.Errorf("sign PDF: %w", err)
	}
	return nil
}

// SignAndEncrypt signs a PDF file and then encrypts it with AES.
// It writes the signed and encrypted result to the destination path.
func (s *Signer) SignAndEncrypt(params SignParams, enc EncryptParams) error {
	if enc.Password == "" {
		return fmt.Errorf("EncryptParams.Password is required")
	}

	srcFile, err := os.Open(params.Src)
	if err != nil {
		return fmt.Errorf("open input PDF: %w", err)
	}
	defer srcFile.Close()

	destPath := params.Dest
	if destPath == "" {
		destPath = params.Src
	}

	// Sign to a temp file, then encrypt to dest.
	tmpFile, err := os.CreateTemp("", "gopdfsigner-*.pdf")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)

	if err := s.SignStream(srcFile, tmpFile, params); err != nil {
		tmpFile.Close()
		return fmt.Errorf("sign PDF: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}

	keyLength := 128
	if enc.AES256 {
		keyLength = 256
	}
	return encryptPDF(tmpPath, destPath, enc.Password, keyLength)
}

// SignBytes signs PDF bytes in memory and returns the signed PDF bytes.
// This is the fastest path when the PDF is already in memory — it operates on
// contiguous byte slices with no io.Copy overhead.
func (s *Signer) SignBytes(pdfData []byte, params SignParams) ([]byte, error) {
	reason, contact, location, page, rect, visible := s.resolveParams(params)
	signingTime := time.Now().UTC()
	srcSize := int64(len(pdfData))

	// Parse PDF structure.
	rs := bytes.NewReader(pdfData)
	ps, err := parsePDFStructure(rs, page)
	if err != nil {
		return nil, err
	}

	// Build incremental update.
	incr, offsets, err := s.buildIncrement(ps, srcSize, reason, contact, location, rect, visible, signingTime)
	defer bufPool.Put(incr)
	if err != nil {
		return nil, err
	}

	incrBytes := incr.Bytes()

	// Combine original + increment into result.
	result := make([]byte, len(pdfData)+len(incrBytes))
	copy(result, pdfData)
	copy(result[len(pdfData):], incrBytes)

	// Compute absolute positions.
	contentValueStart := srcSize + int64(offsets.contentsHexInIncr) - 1
	contentValueEnd := srcSize + int64(offsets.contentsHexEndIncr) + 1
	totalLen := int64(len(result))

	// Patch ByteRange.
	byteRangePos := int(srcSize) + offsets.byteRangeInIncr
	byteRange := fmt.Sprintf("/ByteRange [0 %010d %010d %010d]",
		contentValueStart,
		contentValueEnd,
		totalLen-contentValueEnd,
	)
	if len(byteRange) != len(byteRangePlaceholder) {
		return nil, fmt.Errorf("ByteRange length mismatch: got %d, want %d", len(byteRange), len(byteRangePlaceholder))
	}
	copy(result[byteRangePos:], []byte(byteRange))

	// Hash signed ranges — single Write calls on contiguous slices.
	h := hashPool.Get().(hash.Hash)
	h.Reset()
	h.Write(result[:contentValueStart])
	h.Write(result[contentValueEnd:])
	contentHash := h.Sum(nil)
	hashPool.Put(h)

	// Build PKCS#7 signature.
	rsaKey, ok := s.cfg.Key.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key must be RSA")
	}
	pkcs7Sig, err := buildPKCS7Signature(rsaKey, s.cfg.Chain, contentHash, signingTime)
	if err != nil {
		return nil, fmt.Errorf("build PKCS#7 signature: %w", err)
	}

	// Hex-encode and patch Contents.
	sigHexLen := hex.EncodedLen(len(pkcs7Sig))
	if sigHexLen > contentsPlaceholderLen {
		return nil, fmt.Errorf("PKCS#7 signature too large: %d hex chars (max %d)", sigHexLen, contentsPlaceholderLen)
	}
	contentsHexStart := int(srcSize) + offsets.contentsHexInIncr
	contentsHexEnd := int(srcSize) + offsets.contentsHexEndIncr
	hexBuf := hexBufPool.Get().(*[]byte)
	for i := range *hexBuf {
		(*hexBuf)[i] = '0'
	}
	hex.Encode(*hexBuf, pkcs7Sig)
	for i := 0; i < sigHexLen; i++ {
		c := (*hexBuf)[i]
		if c >= 'a' && c <= 'f' {
			(*hexBuf)[i] = c - 32
		}
	}
	copy(result[contentsHexStart:contentsHexEnd], *hexBuf)
	hexBufPool.Put(hexBuf)

	return result, nil
}
