package entity

import (
	"time"

	"gorm.io/gorm"
)

// Challenge describes either an HTTP-01 or DNS-01 challenge for a requester to solve.
type Challenge struct {
	gorm.Model
	CreatedFor    uint
	RequestInfoID uint
	ChallengeID   string `gorm:"index:,unique"`
	ChallengeType string
	Token         string
	ValidUntil    time.Time
}
