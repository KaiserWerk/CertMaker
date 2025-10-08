package entity

import (
	"github.com/KaiserWerk/CertMaker/internal/global"

	"gorm.io/gorm"
)

// RequestInfo describes the info required to process a certificate request
type RequestInfo struct {
	gorm.Model
	CreatedFor         uint
	CsrBytes           []byte
	SimpleRequestBytes []byte
	Status             global.RequestInfoStatus
}
