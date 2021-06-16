package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/KaiserWerk/CertMaker/internal/assets"
	"github.com/KaiserWerk/CertMaker/internal/certmaker"
	"github.com/KaiserWerk/CertMaker/internal/configuration"
	"github.com/KaiserWerk/CertMaker/internal/dbservice"
	"github.com/KaiserWerk/CertMaker/internal/handler"
	"github.com/KaiserWerk/CertMaker/internal/logging"
	"github.com/KaiserWerk/CertMaker/internal/middleware"
	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"
	"io"
	"net/http"
	"os"
	"os/signal"
	"time"
)

const (
	Version     = "0.0.0"
	VersionDate = "0000-00-00 00:00:00.000 +00:00"
)

var (
	port          = "8880"
	configFilePtr = flag.String("config", "", "The configuration file to use")
	portPtr       = flag.String("port", "", "The port to run at")
	useUiPtr      = flag.Bool("ui", true, "Adds a simple UI for certificate management")
	debugModePtr  = flag.Bool("debug", false, "Run in debug mode")
	logFilePtr    = flag.String("logfile", "certmaker.log", "The path and filename of the log file")
)

func main() {
	flag.Parse()

	logHandle, err := os.OpenFile(*logFilePtr, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0755)
	if err != nil {
		log.Fatal("cannot open or create log file!")
	}
	defer logHandle.Close()

	// set up logger stuff
	var baseLogger = log.New()
	if *debugModePtr {
		baseLogger.SetFormatter(&log.TextFormatter{})
		baseLogger.SetOutput(os.Stdout)
		baseLogger.SetLevel(log.TraceLevel)
	} else {
		baseLogger.SetFormatter(&log.JSONFormatter{})
		baseLogger.SetOutput(io.MultiWriter(os.Stdout, logHandle))
		baseLogger.SetLevel(log.InfoLevel)
	}
	logger := baseLogger.WithFields(log.Fields{"application": "certmaker", "server": "appsrv.lan", "version": Version}) // TODO make server configurable
	logging.SetLogger(logger)

	if *portPtr != "" {
		port = *portPtr
	}

	if *configFilePtr != "" {
		configuration.SetFileSource(*configFilePtr)
	}

	// setup configuration and serial number file, if necessary
	createdConfig, createdSn, err := configuration.Setup()
	if err != nil {
		logger.Fatalf("could not set up configuration: %s", err.Error())
	}

	if createdConfig {
		logger.Debugf("The configuration file was not found so it was created.\nStop execution? (y,n) ")
		var answer string
		_, _ = fmt.Scanln(&answer)
		if answer == "y" {
			logger.Debug("Okay, stopped.")
			os.Exit(0)
		}
	}

	if createdSn {
		logger.Debug("The serial number file was not found so it was created.")
	}

	// create root cert and key, if non-existent
	err = certmaker.SetupCA()
	if err != nil {
		logger.Fatalf("could not set up CA: %s", err.Error())
	}

	// make sure db schema exists
	ds := dbservice.New()
	err = ds.AutoMigrate()
	if err != nil {
		logger.Fatalf("could not execute auto migrations: %s", err.Error())
	}

	// start with the server stuff
	host := fmt.Sprintf(":%s", port)
	router := mux.NewRouter().StrictSlash(true)

	setupRoutes(router, *useUiPtr)

	logger.Debugf("Server listening on %s...", host)

	notify := make(chan os.Signal)
	signal.Notify(notify, os.Interrupt)

	srv := &http.Server{
		Addr:              host,
		Handler:           router,
		ReadTimeout:       2 * time.Second,
		WriteTimeout:      2 * time.Second,
		IdleTimeout:       3 * time.Second,
		ReadHeaderTimeout: 2 * time.Second,
	}

	go func() {
		<-notify
		logger.Debug("Initiating graceful shutdown...")
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		srv.SetKeepAlivesEnabled(false)
		err := srv.Shutdown(ctx)
		if err != nil {
			logger.Fatal("Could not gracefully shut down server: " + err.Error())
		}
	}()

	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logger.Errorf("server error: %s", err.Error())
	}
	logger.Debug("Server shutdown complete.")
}

func setupRoutes(router *mux.Router, ui bool) {
	if ui {
		staticDir := "/static"
		router.
			PathPrefix(staticDir).
			Handler(http.StripPrefix(staticDir, http.FileServer(http.FS(assets.GetStaticFS()))))

		router.HandleFunc("/", middleware.WithSession(handler.IndexHandler)).Methods(http.MethodGet)
		router.HandleFunc("/favicon.ico", handler.FaviconHandler)

		userRouter := router.PathPrefix("/user").Subrouter()
		userRouter.HandleFunc("/profile", middleware.WithSession(handler.ProfileHandler))
		userRouter.HandleFunc("/profile/edit", middleware.WithSession(handler.ProfileEditHandler))
		userRouter.HandleFunc("/regenerate-key", middleware.WithSession(handler.ProfileRegenerateKeyHandler))

		authRouter := router.PathPrefix("/auth").Subrouter()
		authRouter.HandleFunc("/login", handler.LoginHandler).Methods(http.MethodGet, http.MethodPost)
		authRouter.HandleFunc("/logout", middleware.WithSession(handler.LogoutHandler)).Methods(http.MethodGet)
		authRouter.HandleFunc("/register", handler.RegistrationHandler).Methods(http.MethodGet, http.MethodPost)

		certRouter := router.PathPrefix("/certificate").Subrouter()
		certRouter.HandleFunc("/list", middleware.WithSession(middleware.RequireAdmin(handler.CertificateListHandler))).Methods(http.MethodGet)
		certRouter.HandleFunc("/add", middleware.WithSession(handler.CertificateAddHandler)).Methods(http.MethodGet, http.MethodPost)
		certRouter.HandleFunc("/add-with-csr", middleware.WithSession(handler.AddCertificateFromCSRHandler)).Methods(http.MethodGet, http.MethodPost)
		certRouter.HandleFunc("/revoke", middleware.WithSession(handler.RevokeCertificateHandler)).Methods(http.MethodGet, http.MethodPost)

		dlRouter := router.PathPrefix("/download").Subrouter()
		dlRouter.HandleFunc("/certificate/{id}", middleware.WithSession(handler.CertificateDownloadHandler)).Methods(http.MethodGet) // TODO implement
		dlRouter.HandleFunc("/privatekey/{id}", middleware.WithSession(handler.PrivateKeyDownloadHandler)).Methods(http.MethodGet)   // TODO implement

		adminRouter := router.PathPrefix("/admin").Subrouter()
		adminRouter.HandleFunc("/settings", middleware.WithSession(middleware.RequireAdmin(handler.AdminSettingsHandler))).Methods(http.MethodGet, http.MethodPost)
		adminRouter.HandleFunc("/user/list", middleware.WithSession(middleware.RequireAdmin(handler.AdminUserListHandler))).Methods(http.MethodGet)
		adminRouter.HandleFunc("/user/add", middleware.WithSession(middleware.RequireAdmin(handler.AdminUserAddHandler))).Methods(http.MethodGet, http.MethodPost)
		adminRouter.HandleFunc("/user/{id}/edit", middleware.WithSession(middleware.RequireAdmin(handler.AdminUserEditHandler))).Methods(http.MethodGet, http.MethodPost)
		adminRouter.HandleFunc("/user/{id}/remove", middleware.WithSession(middleware.RequireAdmin(handler.AdminUserRemoveHandler))).Methods(http.MethodGet, http.MethodPost)
	}

	apiRouter := router.PathPrefix("/api").Subrouter()
	apiRouter.HandleFunc("/certificate/request", middleware.WithToken(handler.ApiRequestCertificateHandler)).Methods(http.MethodPost)
	apiRouter.HandleFunc("/certificate/request-with-csr", middleware.WithToken(handler.ApiRequestCertificateWithCSRHandler)).Methods(http.MethodPost)
	apiRouter.HandleFunc("/certificate/{id}/obtain", middleware.WithToken(handler.ApiObtainCertificateHandler)).Methods(http.MethodGet)
	apiRouter.HandleFunc("/privatekey/{id}/obtain", middleware.WithToken(handler.ApiObtainPrivateKeyHandler)).Methods(http.MethodGet)
	apiRouter.HandleFunc("/challenge/{token}/solve", middleware.WithToken(nil)).Methods(http.MethodGet) // TODO implement
	apiRouter.HandleFunc("/challenge-with-csr/{token}/solve", middleware.WithToken(nil)).Methods(http.MethodGet) // TODO implement
	apiRouter.HandleFunc("/ocsp/{base64}", handler.ApiOcspRequestHandler).Methods(http.MethodGet, http.MethodPost) // TODO implement
}
