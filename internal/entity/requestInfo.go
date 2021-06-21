package entity

import (
	"gorm.io/gorm"
)

// RequestInfo describes the info required to process a certificate request
type RequestInfo struct {
	gorm.Model
	CreatedFor         uint
	CsrBytes           []byte
	SimpleRequestBytes []byte
	Token              string
	Status             string
}
