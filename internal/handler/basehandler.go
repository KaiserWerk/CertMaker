package handler

import (
	"net/http"

	"github.com/KaiserWerk/CertMaker/internal/certmaker"
	"github.com/KaiserWerk/CertMaker/internal/configuration"
	"github.com/KaiserWerk/CertMaker/internal/dbservice"

	"github.com/KaiserWerk/sessionstore"
	"github.com/sirupsen/logrus"
)

type BaseHandler struct {
	Config    *configuration.AppConfig
	Logger    *logrus.Entry
	DBSvc     *dbservice.DBService
	SessMgr   *sessionstore.SessionManager
	CertMaker *certmaker.CertMaker
	Client    *http.Client
}

func (bh *BaseHandler) ContextLogger(context string) *logrus.Entry {
	return bh.Logger.WithField("context", context)
}
