package entity

import (
	"crypto"
	"crypto/x509"

	"gorm.io/gorm"
)

type Issuer struct {
	gorm.Model
	ParentIssuerID   uint
	SourceID         uint
	SourceType       string
	Context          string `gorm:"index:,unique"`
	Issuer           string
	Subject          string
	SerialNumber     uint64
	NotBefore        string
	NotAfter         string
	Intermediates    []Issuer                   `gorm:"-"`
	FileSystemSource *IssuerFileSystemSource    `gorm:"-"`
	DatabaseSource   *IssuerLocalDatabaseSource `gorm:"-"`
	Certificate      *x509.Certificate          `gorm:"-"`
	PrivateKey       crypto.Signer              `gorm:"-"`
}
