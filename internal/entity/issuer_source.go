package entity

import "gorm.io/gorm"

type IssuerSource struct {
	gorm.Model
	Description string
}
