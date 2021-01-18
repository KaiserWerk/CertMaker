package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/gorilla/mux"
	"log"
	"net/http"
	"os"
	"os/signal"
	"time"
)

var (
	port string
	globalConfig *sysConf
)

func main() {
	flag.StringVar(&port,"port", "8880", "The port to run at")
	flag.Parse()

	var err error
	globalConfig, err = getConfig()
	if err != nil {
		log.Fatal(err.Error())
	}

	err = setupCA()
	if err != nil {
		log.Fatalf("could not set up CA: %s", err.Error())
	}


	host := fmt.Sprintf(":%s", port)

	router := mux.NewRouter()
	setupRoutes(router)
	
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
		log.Println("Initiating graceful shutdown...")
		ctx, cancel := context.WithTimeout(context.Background(), 30 * time.Second)
		defer cancel()
		// do stuff before exiting here

		srv.SetKeepAlivesEnabled(false)
		err := srv.Shutdown(ctx)
		if err != nil {
			log.Fatal("Could not gracefully shut down server: " + err.Error())
		}
	}()

	fmt.Println("Server listening on", host)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Printf("server error: %v\n", err.Error())
	}
	log.Println("Server shutdown complete. Have a nice day!")
}

func setupRoutes(router *mux.Router) {
	router.HandleFunc("/api/certificate/request", certificateRequestHandler)
	router.HandleFunc("/api/certificate/{id}/obtain", certificateObtainHandler)
	router.HandleFunc("/api/privatekey/{id}/obtain", privateKeyObtainHandler)
}



