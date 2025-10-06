package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/KaiserWerk/CertMaker/internal/assets"
	"github.com/KaiserWerk/CertMaker/internal/backup"
	"github.com/KaiserWerk/CertMaker/internal/certmaker"
	"github.com/KaiserWerk/CertMaker/internal/configuration"
	"github.com/KaiserWerk/CertMaker/internal/dbservice"
	"github.com/KaiserWerk/CertMaker/internal/handler"
	"github.com/KaiserWerk/CertMaker/internal/logging"
	"github.com/KaiserWerk/CertMaker/internal/middleware"
	"github.com/KaiserWerk/CertMaker/internal/templating"

	"github.com/KaiserWerk/sessionstore"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
)

var (
	Version     = "0.0.0"
	VersionDate = "0000-00-00 00:00:00"

	configFile = flag.String("config", "config.yaml", "The configuration file to use")
	logPath    = flag.String("logpath", ".", "The path to place log files at")
	port       = flag.String("port", "8880", "The port to run at")
	useUi      = flag.Bool("ui", true, "Adds a simple UI for certificate and instance management")
)

func main() {
	flag.Parse()

	fmt.Println("CertMaker")
	fmt.Printf("  Version %s\n", Version)
	fmt.Printf("  Version Date %s\n\n", VersionDate)

	logger, cleanup, err := logging.New(logrus.DebugLevel, *logPath, "main", logging.ModeFile|logging.ModeConsole)
	defer func() {
		if err := cleanup(); err != nil {
			fmt.Println("could not execute cleanup func:", err.Error())
		}
	}()

	logger.WithFields(logrus.Fields{"application": "certmaker", "version": Version, "versionDate": VersionDate}).Info("app info")

	// setup configuration and serial number file, if necessary
	config, created, err := configuration.Setup(*configFile)
	if err != nil {
		logger.WithField("error", err.Error()).Error("could not set up configuration")
		return
	}
	if created {
		logger.Debugf("The configuration file was not found so it was created.\nExiting...")
		return
	}

	if err = templating.Start(); err != nil {
		logger.WithField("error", err.Error()).Error("could not initialize templates")
		return
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	go backup.StartMakingBackups(ctx, config)

	// create new session manager
	sessMgr := sessionstore.NewManager("CM_SESS")
	// create new certmaker instance and set up CA if necessary
	cm := certmaker.New(config)
	if err := cm.SetupCA(); err != nil {
		logger.WithField("error", err.Error()).Error("could not set up CA")
		return
	}
	// create database service
	ds, err := dbservice.New(config)
	err = ds.AutoMigrate()
	if err != nil {
		logger.WithField("error", err.Error()).Error("could not execute auto migrations")
		return
	}

	router := setupRoutes(config, logger, ds, sessMgr, cm, *useUi)

	host := fmt.Sprintf(":%s", *port)
	srv := &http.Server{
		Addr:              host,
		Handler:           router,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       20 * time.Second,
		ReadHeaderTimeout: 3 * time.Second,
	}

	go func() {
		<-ctx.Done()
		logger.Debug("Initiating graceful shutdown...")
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer shutdownCancel()

		srv.SetKeepAlivesEnabled(false)
		err := srv.Shutdown(shutdownCtx)
		if err != nil {
			logger.WithField("error", err.Error()).Error("could not gracefully shut down server")
		}
	}()

	logger.WithField("host", host).Debugf("Server started listening...")
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.WithField("error", err.Error()).Error("server error")
		return
	}
	logger.Debug("Server shutdown complete.")
}

func setupRoutes(cfg *configuration.AppConfig, logger *logrus.Entry, dbSvc *dbservice.DBService,
	sessMgr *sessionstore.SessionManager, cm *certmaker.CertMaker, ui bool) *mux.Router {

	bh := handler.BaseHandler{
		Config:    cfg,
		Logger:    logger,
		DBSvc:     dbSvc,
		SessMgr:   sessMgr,
		CertMaker: cm,
		Client:    &http.Client{Timeout: 10 * time.Second},
	}

	mh := middleware.MWHandler{
		Config:  cfg,
		Logger:  logger,
		DBSvc:   dbSvc,
		SessMgr: sessMgr,
	}

	router := mux.NewRouter().StrictSlash(true)

	if ui {
		staticDir := "/static"
		router.
			PathPrefix(staticDir).
			Handler(http.StripPrefix(staticDir, http.FileServer(http.FS(assets.GetStaticFS()))))

		defaultRouter := router.PathPrefix("/").Subrouter()
		defaultRouter.Use(mh.WithSession)
		defaultRouter.HandleFunc("/", bh.IndexHandler).Methods(http.MethodGet)
		defaultRouter.HandleFunc("/favicon.ico", bh.FaviconHandler)
		defaultRouter.HandleFunc("/root-certificate/download", bh.RootCertificateDownloadHandler).Methods(http.MethodGet)
		defaultRouter.HandleFunc("/privatekey/{id}/download", bh.PrivateKeyDownloadHandler).Methods(http.MethodGet)

		userRouter := router.PathPrefix("/user").Subrouter()
		userRouter.Use(mh.WithSession)
		userRouter.HandleFunc("/profile", bh.ProfileHandler)
		userRouter.HandleFunc("/profile/edit", bh.ProfileEditHandler)
		userRouter.HandleFunc("/regenerate-key", bh.ProfileRegenerateKeyHandler)

		authRouter := router.PathPrefix("/auth").Subrouter()
		authRouter.HandleFunc("/login", bh.LoginHandler).Methods(http.MethodGet, http.MethodPost)
		authRouter.HandleFunc("/logout", bh.LogoutHandler).Methods(http.MethodGet)
		authRouter.HandleFunc("/register", bh.RegistrationHandler).Methods(http.MethodGet, http.MethodPost)

		certRouter := router.PathPrefix("/certificate").Subrouter()
		certRouter.Use(mh.WithSession)
		certRouter.HandleFunc("/list", bh.CertificateListHandler).Methods(http.MethodGet)
		certRouter.HandleFunc("/add", bh.CertificateAddHandler).Methods(http.MethodGet, http.MethodPost)
		certRouter.HandleFunc("/add-with-csr", bh.AddCertificateFromCSRHandler).Methods(http.MethodGet, http.MethodPost)
		certRouter.HandleFunc("/{id}/revoke", bh.RevokeCertificateHandler).Methods(http.MethodGet, http.MethodPost)
		certRouter.HandleFunc("/{id}/download", bh.CertificateDownloadHandler).Methods(http.MethodGet)

		adminRouter := router.PathPrefix("/admin").Subrouter()
		adminRouter.Use(mh.WithSession, mh.RequireAdmin)
		adminRouter.HandleFunc("/settings", bh.AdminSettingsHandler).Methods(http.MethodGet, http.MethodPost)
		adminRouter.HandleFunc("/user/list", bh.AdminUserListHandler).Methods(http.MethodGet)
		adminRouter.HandleFunc("/user/add", bh.AdminUserAddHandler).Methods(http.MethodGet, http.MethodPost)
		adminRouter.HandleFunc("/user/{id}/edit", bh.AdminUserEditHandler).Methods(http.MethodGet, http.MethodPost)
		adminRouter.HandleFunc("/user/{id}/remove", bh.AdminUserRemoveHandler).Methods(http.MethodGet, http.MethodPost)
	}

	apiRouter := router.PathPrefix("/api/v1").Subrouter()
	apiRouter.Use(mh.WithToken)
	apiRouter.HandleFunc("/root-certificate/obtain", bh.ApiRootCertificateDownloadHandler).Methods(http.MethodGet)
	apiRouter.HandleFunc("/certificate/request", bh.ApiRequestCertificateHandler).Methods(http.MethodPost)
	apiRouter.HandleFunc("/certificate/request-with-csr", bh.ApiRequestCertificateWithCSRHandler).Methods(http.MethodPost)
	apiRouter.HandleFunc("/certificate/{id}/obtain", bh.ApiObtainCertificateHandler).Methods(http.MethodGet)
	apiRouter.HandleFunc("/certificate/{sn}/revoke", bh.ApiRevokeCertificateHandler).Methods(http.MethodGet)
	apiRouter.HandleFunc("/privatekey/{id}/obtain", bh.ApiObtainPrivateKeyHandler).Methods(http.MethodGet)
	apiRouter.HandleFunc("/challenge/{id}/solve", bh.ApiSolveChallengeHandler).Methods(http.MethodGet)

	ocspRouter := router.PathPrefix("/ocsp").Subrouter()
	ocspRouter.HandleFunc("/ocsp/{base64}", bh.ApiOcspRequestHandler).Methods(http.MethodGet, http.MethodPost)
	ocspRouter.HandleFunc("/ocsp", bh.ApiOcspRequestHandler).Methods(http.MethodGet, http.MethodPost)

	return router
}
