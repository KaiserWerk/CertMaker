package entity

import (
	"gorm.io/gorm"
)

type Configuration struct {
	ServerHost string `yaml:"server_host"`
	DataDir    string `yaml:"data_dir"`
	Database struct {
		Driver string `yaml:"driver"`
		DSN string `yaml:"dsn"`
	} `yaml:"database"`
}

type CertificateRequest struct {
	Domains []string `json:"domains"`
	IPs     []string `json:"ips"`
	Subject struct {
		Organization  string `json:"organization"`
		Country       string `json:"country"`
		Province      string `json:"province"`
		Locality      string `json:"locality"`
		StreetAddress string `json:"street_address"`
		PostalCode    string `json:"postal_code"`
	} `json:"subject"`
	Days int `json:"days"`
}

type User struct {
	gorm.Model
	Username string
	Password string
	ApiKey string
	NoLogin bool
	Locked bool
}
