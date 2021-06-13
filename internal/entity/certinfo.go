package entity

import "gorm.io/gorm"

// CertInfo represents the information saved in the
// database about a single generated certificate
type CertInfo struct {
	gorm.Model
	SerialNumber   int64 `gorm:"index:,unique"`
	FromCSR        bool
	CreatedForUser uint
	Revoked        bool
	RevokedBecause string
}
