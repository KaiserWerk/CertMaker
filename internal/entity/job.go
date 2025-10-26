package entity

import "gorm.io/gorm"

type Job struct {
	gorm.Model
	Caption  string `gorm:"uniqueIndex;not null"`
	Interval string `gorm:"not null"` // e.g., "4h", "24h"
}
