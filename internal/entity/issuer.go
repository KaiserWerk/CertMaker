package entity

import (
	"crypto"
	"crypto/x509"
	"time"

	"gorm.io/gorm"
)

type Issuer struct {
	gorm.Model
	ParentIssuerID uint
	Name           string
	Issuer         string
	Subject        string
	SerialNumber   uint64
	NotBefore      time.Time
	NotAfter       time.Time
	CertificatePEM []byte
	PrivateKeyPEM  []byte
	Intermediates  []*Issuer         `gorm:"-"`
	Certificate    *x509.Certificate `gorm:"-"`
	PrivateKey     crypto.Signer     `gorm:"-"`
}
