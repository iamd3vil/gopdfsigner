package gopdfsigner

import (
	"fmt"
	"strings"
	"time"
)

func buildAppearanceStream(rect Rectangle, signerName, reason, location string, signingTime time.Time) []byte {
	width := rect.X2 - rect.X1
	height := rect.Y2 - rect.Y1

	// Count lines to calculate font size that fits the box.
	lineCount := 3 // "Digitally signed by:", signer name, date
	if reason != "" {
		lineCount++
	}
	if location != "" {
		lineCount++
	}

	// Each line needs fontSize * 1.3 (line height) plus top/bottom padding.
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
	startY := height - padding - fontSize

	var b strings.Builder

	// Background fill and border.
	fmt.Fprintf(&b, "q\n")
	fmt.Fprintf(&b, "1 1 0.8 rg\n")
	fmt.Fprintf(&b, "0 0 %g %g re f\n", width, height)
	fmt.Fprintf(&b, "0 0 0 RG 0.5 w\n")
	fmt.Fprintf(&b, "0 0 %g %g re S\n", width, height)
	fmt.Fprintf(&b, "Q\n")

	// Text.
	fmt.Fprintf(&b, "BT\n")
	fmt.Fprintf(&b, "/F1 %.1f Tf\n", fontSize)
	fmt.Fprintf(&b, "0 0.4 0 rg\n")
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

func pdfEscapeString(s string) string {
	replacer := strings.NewReplacer(`\`, `\\`, `(`, `\(`, `)`, `\)`)
	return replacer.Replace(s)
}
