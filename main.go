package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"github.com/gorilla/mux"
	"net/http"
	"os"
	"os/signal"
	"time"
)

var (
	port string

)

func main() {
	caDir := "ca"
	certFilename := "ca-cert.pem"
	keyFilename := "ca-priv.pem"

	err := setupCA(caDir, certFilename, keyFilename)
	if err != nil {
		panic("could not setup app: " + err.Error())
	}

	flag.StringVar(&port,"port", "8880", "The port to run at")
	host := fmt.Sprintf(":%s", port)

	router := mux.NewRouter()

	// catch ctrl+c for graceful shutdown
	notify := make(chan os.Signal)
	signal.Notify(notify, os.Interrupt)

	srv := &http.Server{
		Addr: 				host,
		Handler:            router,
		ReadTimeout:		2 * time.Second,
		WriteTimeout:       2 * time.Second,
		IdleTimeout:        3 * time.Second,
		ReadHeaderTimeout:  2 * time.Second,
	}

	go func() {
		<-notify
		fmt.Println("Initiating graceful shutdown...")
		ctx, cancel := context.WithTimeout(context.Background(), 30 * time.Second)
		defer cancel()
		// do stuff before exiting here

		srv.SetKeepAlivesEnabled(false)
		err := srv.Shutdown(ctx)
		if err != nil {
			panic("Could not gracefully shut down server: " + err.Error())
		}
	}()

	fmt.Println("Server listening on", host)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		fmt.Printf("server error: %v\n", err.Error())
	}
	fmt.Println("Server shutdown complete. Have a nice day!")
}

func setupCA(caDir, certFilename, keyFilename string) error {
	certFile := fmt.Sprintf("%s/%s", caDir, certFilename)
	keyFile := fmt.Sprintf("%s/%s", caDir, keyFilename)

	// check if root certificate exists
	if !doesFileExist(certFile) || !doesFileExist(keyFile) {
		// if no, generate new one and save to file
		if err := generateRootCertAndKey(caDir, certFilename, keyFilename); err != nil {
			return err
		}
	}

	// if yes, try to load it. return error, if any
	caFiles, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return err
	}
	// parse the content
	_, err = x509.ParseCertificate(caFiles.Certificate[0])
	if err != nil {
		return err
	}

	return nil
}


