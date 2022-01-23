package handler

import (
	"github.com/KaiserWerk/CertMaker/internal/certmaker"
	"github.com/KaiserWerk/CertMaker/internal/configuration"
	"github.com/KaiserWerk/CertMaker/internal/dbservice"
	"github.com/KaiserWerk/CertMaker/internal/templates"
	"github.com/KaiserWerk/sessionstore"
	"github.com/sirupsen/logrus"
	"net/http"
)

type BaseHandler struct {
	Config  *configuration.AppConfig
	Logger  *logrus.Entry
	DBSvc   *dbservice.DBService
	SessMgr *sessionstore.SessionManager
	CM      *certmaker.CertMaker
	Client  *http.Client
}

func (bh *BaseHandler) ContextLogger(context string) *logrus.Entry {
	return bh.Logger.WithField("context", context)
}

func (bh *BaseHandler) Inj() *templates.TplInjector {
	return &templates.TplInjector{
		Logger: bh.Logger,
	}
}
