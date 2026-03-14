package gosigner

import (
	"github.com/pdfcpu/pdfcpu/pkg/api"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/model"
)

func encryptPDF(inputPath, outputPath, password string, keyLength int) error {
	if keyLength != 128 && keyLength != 256 {
		keyLength = 128
	}
	conf := model.NewAESConfiguration(password, password, keyLength)
	conf.Permissions = model.PermissionsPrint

	return api.EncryptFile(inputPath, outputPath, conf)
}
