package gopdfsigner

import (
	"fmt"
	"strings"
	"time"
)

// buildAppearanceStream generates a PDF content stream for the visible signature box.
// The stream draws a light yellow background with a thin border, then renders
// signature details as green text. The font size auto-scales to fit the rectangle,
// clamped between 4pt (minimum legibility) and 10pt (maximum).
//
// The returned bytes are meant to be embedded in a Form XObject's stream.
func buildAppearanceStream(rect Rectangle, signerName, reason, location string, signingTime time.Time) []byte {
	width := rect.X2 - rect.X1
	height := rect.Y2 - rect.Y1

	// Count lines to calculate font size that fits the box.
	lineCount := 3 // always: "Digitally signed by:", signer name, date
	if reason != "" {
		lineCount++
	}
	if location != "" {
		lineCount++
	}

	// Auto-scale font: divide available height by total line height needed.
	// lineHeight = fontSize * 1.3 gives comfortable inter-line spacing.
	padding := 4.0
	availableHeight := height - 2*padding
	fontSize := availableHeight / (float64(lineCount) * 1.3)
	if fontSize > 10 {
		fontSize = 10
	}
	if fontSize < 4 {
		fontSize = 4
	}
	lineHeight := fontSize * 1.3
	startY := height - padding - fontSize // first baseline position (top-down)

	var b strings.Builder

	// Background fill and border using PDF graphics operators:
	//   q/Q = save/restore graphics state
	//   rg  = set fill color (RGB), RG = set stroke color (RGB)
	//   re  = rectangle path, f = fill, S = stroke
	//   w   = set line width
	fmt.Fprintf(&b, "q\n")                             // save state
	fmt.Fprintf(&b, "1 1 0.8 rg\n")                    // fill color: light yellow
	fmt.Fprintf(&b, "0 0 %g %g re f\n", width, height) // filled rectangle
	fmt.Fprintf(&b, "0 0 0 RG 0.5 w\n")                // stroke: black, 0.5pt
	fmt.Fprintf(&b, "0 0 %g %g re S\n", width, height) // stroked border
	fmt.Fprintf(&b, "Q\n")                             // restore state

	// Text block using PDF text operators:
	//   BT/ET = begin/end text object
	//   Tf    = set font and size
	//   Td    = move text position (relative)
	//   Tj    = show text string
	fmt.Fprintf(&b, "BT\n")
	fmt.Fprintf(&b, "/F1 %.1f Tf\n", fontSize)
	fmt.Fprintf(&b, "0 0.4 0 rg\n") // text color: dark green
	fmt.Fprintf(&b, "4 %.2f Td (%s) Tj\n", startY, pdfEscapeString("Digitally signed by:"))
	fmt.Fprintf(&b, "0 %.2f Td (%s) Tj\n", -lineHeight, pdfEscapeString(signerName))
	fmt.Fprintf(&b, "0 %.2f Td (%s) Tj\n", -lineHeight, pdfEscapeString("Date: "+signingTime.UTC().Format("2006-01-02 15:04:05 UTC")))

	if reason != "" {
		fmt.Fprintf(&b, "0 %.2f Td (%s) Tj\n", -lineHeight, pdfEscapeString("Reason: "+reason))
	}

	if location != "" {
		fmt.Fprintf(&b, "0 %.2f Td (%s) Tj\n", -lineHeight, pdfEscapeString("Location: "+location))
	}

	fmt.Fprintf(&b, "ET\n")

	return []byte(b.String())
}

// pdfStringReplacer is a pre-built replacer for PDF string escaping.
// Created once to avoid repeated allocation and trie building per call.
var pdfStringReplacer = strings.NewReplacer(`\`, `\\`, `(`, `\(`, `)`, `\)`)

// pdfEscapeString escapes special characters for a PDF literal string.
// PDF strings are delimited by parentheses, so (, ), and \ must be escaped.
func pdfEscapeString(s string) string {
	return pdfStringReplacer.Replace(s)
}
