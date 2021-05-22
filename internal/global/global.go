package global

import (
	"github.com/KaiserWerk/CertMaker/internal/entity"
	"github.com/KaiserWerk/sessionstore"
)

var (
	config *entity.Configuration
	sessMgr *sessionstore.SessionManager
)

func init() {
	sessMgr = sessionstore.NewManager("CERTMAKERSESS")
}

func SetConfiguration(c *entity.Configuration) {
	config = c
}

func GetConfiguration() *entity.Configuration {
	return config
}

func GetSessMgr() *sessionstore.SessionManager {
	return sessMgr
}
