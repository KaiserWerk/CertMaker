package entity

import "gorm.io/gorm"

type CsrInfo struct {
	gorm.Model
	CreatedForUser uint
	Token string
	CsrData []byte
}
