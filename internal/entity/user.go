package entity

import "gorm.io/gorm"

// User defines a user account in the CertMaker system
type User struct {
	gorm.Model
	Username string   `gorm:"index:,unique"`
	Email    string   `gorm:"default:'',index:,unique"`
	Password string   `gorm:"size:255"`
	NoLogin  bool     `gorm:"default:0"`
	Locked   bool     `gorm:"default:0"`
	Admin    bool     `gorm:"default:0"`
	ApiKeys  []APIKey `gorm:"-"`
}
