package entity

import "gorm.io/gorm"

type IssuerFileSystemSource struct {
	gorm.Model
	CertificateFile string
	KeyFile         string
}
