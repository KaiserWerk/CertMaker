package middleware

import (
	"github.com/KaiserWerk/CertMaker/internal/configuration"
	"github.com/KaiserWerk/CertMaker/internal/dbservice"

	"github.com/KaiserWerk/sessionstore"
	"github.com/sirupsen/logrus"
)

type MWHandler struct {
	Config  *configuration.AppConfig
	Logger  *logrus.Entry
	DBSvc   *dbservice.DBService
	SessMgr *sessionstore.SessionManager
}

func (mh *MWHandler) ContextLogger(context string) *logrus.Entry {
	return mh.Logger.WithField("context", context)
}
