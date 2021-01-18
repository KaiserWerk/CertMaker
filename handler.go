package main

import (
	"encoding/json"
	"net/http"
)

func certificateRequestHandler(w http.ResponseWriter, r *http.Request) {
	// dont forget authentication

	var certRequest certificateRequest
	err := json.NewDecoder(r.Body).Decode(&certRequest)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
	}
	_ = r.Body.Close()

	// generate private key + cert
	// store both in files
	// set location headers to both

}

func certificateObtainHandler(w http.ResponseWriter, r *http.Request) {

}

func privateKeyObtainHandler(w http.ResponseWriter, r *http.Request) {

}
