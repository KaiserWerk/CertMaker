package entity

import "gorm.io/gorm"

// SystemSetting defines a single entry of a system setting
type SystemSetting struct {
	gorm.Model
	Name string `gorm:"index:,unique"`
	Value string
}
