package entity

import "gorm.io/gorm"

type APIKey struct {
	gorm.Model
	UserID         uint   `gorm:"index"`
	Key            string `gorm:"index:,unique"`
	Name           string
	AllowedIssuers string // comma-separated list of issuer IDs
}
