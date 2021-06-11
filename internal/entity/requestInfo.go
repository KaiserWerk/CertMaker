package entity

import "gorm.io/gorm"

type RequestInfo struct {
	gorm.Model
	Domains        string
	IpAddresses    string
	EmailAddresses string
	Days           int
	Token          string
}