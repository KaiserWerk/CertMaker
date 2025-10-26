package entity

import "gorm.io/gorm"

type IssuerLocalDatabaseSource struct {
	gorm.Model
	CertificatePEM []byte
	KeyPEM         []byte
}
