package entity

import "gorm.io/gorm"

type SystemSetting struct {
	gorm.Model
	Name string `gorm:"index:,unique"`
	Value string
}
