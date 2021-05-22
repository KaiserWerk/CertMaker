package entity

import "gorm.io/gorm"

type User struct {
	gorm.Model
	Username string `gorm:"index:,unique"`
	Email string `gorm:"index:,unique"`
	Password string `gorm:"size:150"`
	ApiKey string `gorm:"index:,unique"`
	NoLogin bool
	Locked bool
}
