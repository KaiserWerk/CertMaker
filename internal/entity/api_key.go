package entity

import "gorm.io/gorm"

type APIKey struct {
	gorm.Model
	UserID         uint   `gorm:"index"`
	Key            string `gorm:"index:,unique"`
	AllowedIssuers string `gorm:"type:text"` // comma-separated list of issuer IDs
}
