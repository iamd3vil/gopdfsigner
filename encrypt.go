package gosigner

import (
	"github.com/pdfcpu/pdfcpu/pkg/api"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/model"
)

func encryptPDF(inputPath, outputPath, password string) error {
	conf := model.NewAESConfiguration(password, password, 128)
	conf.Permissions = model.PermissionsPrint

	return api.EncryptFile(inputPath, outputPath, conf)
}
