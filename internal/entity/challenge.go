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
	ChallengeID   string
	ChallengeType string
	//Domains       string // Comma-separated list of domains this challenge is for
	Token      string
	ValidUntil time.Time
}
