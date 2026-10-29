package entity

import "gorm.io/gorm"

type APIKey struct {
	gorm.Model
	UserID     uint   `gorm:"index"`
	IssuerID   uint   `gorm:"index"`
	KeyContent string `gorm:"index:,unique"`
	Name       string
}
