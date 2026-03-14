package gopdfsigner

import (
	"io"

	"github.com/pdfcpu/pdfcpu/pkg/api"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/model"
)

// encryptPDF applies AES encryption to a PDF file using pdfcpu.
// The same password is used for both the user password (required to open) and
// the owner password (required to change permissions). Only print permission is
// granted — editing, copying, and annotation are restricted.
func encryptPDF(inputPath, outputPath, password string, keyLength int) error {
	if keyLength != 128 && keyLength != 256 {
		keyLength = 128
	}
	conf := model.NewAESConfiguration(password, password, keyLength)
	conf.Permissions = model.PermissionsPrint

	return api.EncryptFile(inputPath, outputPath, conf)
}

// newEncryptConf creates a pdfcpu AES encryption configuration.
// Optimization is disabled since we only need encryption, not PDF restructuring.
func newEncryptConf(password string, keyLength int) *model.Configuration {
	if keyLength != 128 && keyLength != 256 {
		keyLength = 128
	}
	conf := model.NewAESConfiguration(password, password, keyLength)
	conf.Permissions = model.PermissionsPrint
	// Disable optimization — we only need to encrypt, not restructure the PDF.
	// This saves significant time by skipping xref table optimization.
	conf.Optimize = false
	conf.OptimizeBeforeWriting = false
	conf.OptimizeResourceDicts = false
	// Don't validate links (unnecessary for encryption).
	conf.ValidateLinks = false
	return conf
}

// encryptPDFStream encrypts PDF data from a ReadSeeker and writes to a Writer.
// It uses a custom pipeline that skips PDF validation (the input was just signed
// by us, so we know it's valid) to save ~5% of encryption time.
func encryptPDFStream(rs io.ReadSeeker, w io.Writer, password string, keyLength int) error {
	conf := newEncryptConf(password, keyLength)
	conf.Cmd = model.ENCRYPT

	// Read PDF context without validation — we just signed this PDF, it's valid.
	ctx, err := api.ReadContext(rs, conf)
	if err != nil {
		return err
	}

	// Write the encrypted context.
	return api.WriteContext(ctx, w)
}
