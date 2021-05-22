package entity

import "gorm.io/gorm"

type CertInfo struct {
	gorm.Model
	SerialNumber int64 `gorm:"index:,unique"`
	CreatedForUser int
	Revoked bool
	RevokedBecause string
}