package main

import (
	"encoding/json"
	"fmt"
	"github.com/gorilla/mux"
	"log"
	"net/http"
)

func certificateRequestHandler(w http.ResponseWriter, r *http.Request) {
	// dont forget authentication

	var certRequest certificateRequest
	err := json.NewDecoder(r.Body).Decode(&certRequest)
	if err != nil {
		log.Printf("error parsing certificate request: %s\n", err.Error())
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	_ = r.Body.Close()

	sn, err := generateLeafCertAndKey(certRequest)
	if err != nil {
		log.Printf("error generating key + certificate: %s\n", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Add("X-Certificate-Location", fmt.Sprintf("http://%s/api/certificate/%d/obtain", globalConfig.ServerHost, sn))
	w.Header().Add("X-Privatekey-Location", fmt.Sprintf("http://%s/api/privatekey/%d/obtain", globalConfig.ServerHost, sn))
}

func certificateObtainHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	certBytes, err := findLeafCertificate(id)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	_, _ = w.Write(certBytes)
}

func privateKeyObtainHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	keyBytes, err := findPrivateKey(id)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	_, err = w.Write(keyBytes)
	if err != nil {
		log.Println("could not write privkey bytes:", err.Error())
	}
}
