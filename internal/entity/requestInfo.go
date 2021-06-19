package entity

import (
	"gorm.io/gorm"
)

type RequestInfo struct {
	gorm.Model
	CsrBytes           []byte
	SimpleRequestBytes []byte
	Token              string
	Status             string
}
