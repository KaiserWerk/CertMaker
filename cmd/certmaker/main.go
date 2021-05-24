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
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"time"
)

var (
	port = "8880"
)

func main() {
	var err error
	configFilePtr := flag.String("config", "", "The configuration file to use")
	portPtr := flag.String("port", "", "The port to run at")
	useUiPtr := flag.Bool("ui", true, "Adds a simple UI for certificate management")
	asServicePtr := flag.Bool("as-service", false, "Whether to run in service mode")
	flag.Parse()

	logHandle, err := os.Create("certmaker.log")
	if err != nil {
		log.Fatal("cannot create log file!")
	}
	defer logHandle.Close()
	//log.SetOutput(io.MultiWriter(os.Stdout, logHandle))

	// set up logger stuff
	var logger *log.Logger
	if *asServicePtr {
		// log to file as well
		logger = log.New(io.MultiWriter(os.Stdout, logHandle), "", 0)
	} else {
		logger = log.New(os.Stdout, "", log.LstdFlags | log.Lmicroseconds)
	}
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
		logger.Printf("The configuration file was not found; created\n\tStop execution? (y,n)")
		var answer string
		_, _ = fmt.Scanln(&answer)
		if answer == "y" {
			logger.Fatalf("Okay, stopped.")
		}
	}

	if createdSn {
		logger.Printf("The serial number was file not found; created")
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

	logger.Printf("Server listening on %s...\n", host)

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
		logger.Println("Initiating graceful shutdown...")
		ctx, cancel := context.WithTimeout(context.Background(), 30 * time.Second)
		defer cancel()
		// do necessary stuff here before we exit

		srv.SetKeepAlivesEnabled(false)
		err := srv.Shutdown(ctx)
		if err != nil {
			logger.Fatal("Could not gracefully shut down server: " + err.Error())
		}
	}()

	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logger.Printf("server error: %v\n", err.Error())
	}
	logger.Println("Server shutdown complete.")
}

func setupRoutes(router *mux.Router, ui bool) {
	if ui {
		staticDir := "/static"
		router.
			PathPrefix(staticDir).
			Handler(http.StripPrefix(staticDir, http.FileServer(http.FS(assets.GetStaticFS()))))

		router.HandleFunc("/", middleware.WithSession(handler.IndexHandler)).Methods(http.MethodGet)

		authRouter := router.PathPrefix("/auth").Subrouter()
		authRouter.HandleFunc("/login", handler.LoginHandler).Methods(http.MethodGet, http.MethodPost)
		authRouter.HandleFunc("/logout", middleware.WithSession(handler.LogoutHandler)).Methods(http.MethodGet)
		authRouter.HandleFunc("/register", handler.RegistrationHandler).Methods(http.MethodGet, http.MethodPost)

		certRouter := router.PathPrefix("/certificate").Subrouter()
		certRouter.HandleFunc("/list", middleware.WithSession(handler.ListCertificateHandler)).Methods(http.MethodGet)
		certRouter.HandleFunc("/add", middleware.WithSession(handler.AddCertificateHandler)).Methods(http.MethodGet, http.MethodPost)
		certRouter.HandleFunc("/add-with-csr", middleware.WithSession(handler.AddCertificateWithCSRHandler)).Methods(http.MethodGet, http.MethodPost)
		certRouter.HandleFunc("/revoke", middleware.WithSession(handler.RevokeCertificateHandler)).Methods(http.MethodGet, http.MethodPost) // TODO implement with cert upload form

		adminRouter := router.PathPrefix("/admin").Subrouter()
		adminRouter.HandleFunc("/settings", middleware.WithSession(middleware.RequireAdmin(handler.AdminSettingsHandler))).Methods(http.MethodGet, http.MethodPost)
		adminRouter.HandleFunc("/user/list", middleware.WithSession(middleware.RequireAdmin(handler.AdminUserListHandler))).Methods(http.MethodGet)
		adminRouter.HandleFunc("/user/add", middleware.WithSession(middleware.RequireAdmin(handler.AdminUserAddHandler))).Methods(http.MethodGet, http.MethodPost)
		adminRouter.HandleFunc("/user/{id}/edit", middleware.WithSession(middleware.RequireAdmin(handler.AdminUserEditHandler))).Methods(http.MethodGet, http.MethodPost)
		adminRouter.HandleFunc("/user/{id}/remove", middleware.WithSession(middleware.RequireAdmin(handler.AdminUserRemoveHandler))).Methods(http.MethodGet, http.MethodPost)
	}
	apiRouter := router.PathPrefix("/api").Subrouter()
	apiRouter.HandleFunc("/certificate/request", middleware.WithToken(handler.ApiRequestCertificateHandler)).Methods(http.MethodPost)
	apiRouter.HandleFunc("/certificate/{id}/obtain", middleware.WithToken(handler.ApiObtainCertificateHandler)).Methods(http.MethodGet)
	apiRouter.HandleFunc("/privatekey/{id}/obtain", middleware.WithToken(handler.ApiObtainPrivateKeyHandler)).Methods(http.MethodGet)
	apiRouter.HandleFunc("/ocsp/", handler.ApiOcspRequestHandler).Methods(http.MethodPost) // TODO only post?
}


