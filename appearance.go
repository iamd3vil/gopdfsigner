package gosigner

import (
	"fmt"
	"strings"
	"time"
)

func buildAppearanceStream(rect Rectangle, signerName, reason, location string, signingTime time.Time) []byte {
	width := rect.X2 - rect.X1
	height := rect.Y2 - rect.Y1
	startY := height - 15

	var b strings.Builder

	fmt.Fprintf(&b, "q\n")
	fmt.Fprintf(&b, "1 1 0.8 rg\n")
	fmt.Fprintf(&b, "0 0 %g %g re f\n", width, height)
	fmt.Fprintf(&b, "0 0 0 RG 1 w\n")
	fmt.Fprintf(&b, "0 0 %g %g re S\n", width, height)
	fmt.Fprintf(&b, "Q\n")
	fmt.Fprintf(&b, "BT\n")
	fmt.Fprintf(&b, "/F1 9 Tf\n")
	fmt.Fprintf(&b, "0 0.4 0 rg\n")
	fmt.Fprintf(&b, "5 %g Td (%s) Tj\n", startY, pdfEscapeString("Digitally signed by:"))
	fmt.Fprintf(&b, "0 -12 Td (%s) Tj\n", pdfEscapeString(signerName))
	fmt.Fprintf(&b, "0 -12 Td (%s) Tj\n", pdfEscapeString("Date: "+signingTime.UTC().Format("2006-01-02 15:04:05 UTC")))

	if reason != "" {
		fmt.Fprintf(&b, "0 -12 Td (%s) Tj\n", pdfEscapeString("Reason: "+reason))
	}

	if location != "" {
		fmt.Fprintf(&b, "0 -12 Td (%s) Tj\n", pdfEscapeString("Location: "+location))
	}

	fmt.Fprintf(&b, "ET\n")

	return []byte(b.String())
}

func pdfEscapeString(s string) string {
	replacer := strings.NewReplacer(`\`, `\\`, `(`, `\(`, `)`, `\)`)
	return replacer.Replace(s)
}
