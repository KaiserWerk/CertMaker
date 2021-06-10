package global

import (
	"github.com/KaiserWerk/CertMaker/internal/entity"
	"github.com/KaiserWerk/sessionstore"
)

const (
	CertificateMinDays = 1
	CertificateMaxDays = 182
	CertificateDefaultDays = 7
)

var (
	config *entity.Configuration
	sessMgr *sessionstore.SessionManager
)

func init() {
	sessMgr = sessionstore.NewManager("CERTMAKERSESS")
}

// SetConfiguration sets the global configuration to a given object
func SetConfiguration(c *entity.Configuration) {
	config = c
}

// GetConfiguration fetches the global configuration
func GetConfiguration() *entity.Configuration {
	return config
}

// GetSessMgr fetches the global SessionManager
func GetSessMgr() *sessionstore.SessionManager {
	return sessMgr
}
