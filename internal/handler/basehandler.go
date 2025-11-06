package handler

import (
	"net/http"

	"github.com/KaiserWerk/CertMaker/internal/configuration"
	"github.com/KaiserWerk/CertMaker/internal/cron"
	"github.com/KaiserWerk/CertMaker/internal/dbservice"

	"github.com/KaiserWerk/sessionstore"
	"github.com/sirupsen/logrus"
)

type BaseHandler struct {
	Config  *configuration.AppConfig
	Logger  *logrus.Entry
	DBSvc   *dbservice.DBService
	SessMgr *sessionstore.SessionManager
	CronSvc *cron.Cron
	Client  *http.Client
}

func (bh *BaseHandler) ContextLogger(context string) *logrus.Entry {
	return bh.Logger.WithField("context", context)
}
