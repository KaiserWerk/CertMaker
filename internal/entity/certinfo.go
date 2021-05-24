package entity

import "gorm.io/gorm"

// CertInfo represents the information saved in the
// database about a single generated certificate
type CertInfo struct {
	gorm.Model
	SerialNumber int64 `gorm:"index:,unique"`
	CreatedForUser int
	Revoked bool
	RevokedBecause string
}