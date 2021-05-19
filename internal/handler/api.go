package handler

import (
	"encoding/json"
	"fmt"
	"github.com/KaiserWerk/CertMaker/internal/certmaker"
	"github.com/KaiserWerk/CertMaker/internal/entity"
	"github.com/KaiserWerk/CertMaker/internal/global"
	"github.com/KaiserWerk/CertMaker/internal/logging"
	"github.com/gorilla/mux"
	"golang.org/x/crypto/ocsp"
	"io/ioutil"
	"net/http"
)

func ApiRequestCertificateHandler(w http.ResponseWriter, r *http.Request) {
	// dont forget authentication
	config := global.GetConfiguration()
	logger := logging.GetLogger()
	var certRequest entity.CertificateRequest
	err := json.NewDecoder(r.Body).Decode(&certRequest)
	if err != nil {
		logger.Printf("error parsing certificate request: %s\n", err.Error())
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	_ = r.Body.Close()

	sn, err := certmaker.GenerateLeafCertAndKey(certRequest)
	if err != nil {
		logger.Printf("error generating key + certificate: %s\n", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Add("X-Certificate-Location", fmt.Sprintf("http://%s/api/certificate/%d/obtain", config.ServerHost, sn))
	w.Header().Add("X-Privatekey-Location", fmt.Sprintf("http://%s/api/privatekey/%d/obtain", config.ServerHost, sn))
}

func ApiObtainCertificateHandler(w http.ResponseWriter, r *http.Request) {
	logger := logging.GetLogger()
	vars := mux.Vars(r)
	id := vars["id"]

	certBytes, err := certmaker.FindLeafCertificate(id)
	if err != nil {
		logger.Printf("No certificate found for ID %s\n", id)
		w.WriteHeader(http.StatusNotFound)
		return
	}

	_, err = w.Write(certBytes)
	if err != nil {
		logger.Println("could not write cert bytes:", err.Error())
	}
}

func ApiObtainPrivateKeyHandler(w http.ResponseWriter, r *http.Request) {
	logger := logging.GetLogger()
	vars := mux.Vars(r)
	id := vars["id"]

	keyBytes, err := certmaker.FindLeafPrivateKey(id)
	if err != nil {
		logger.Printf("No private key found for ID %s\n", id)
		w.WriteHeader(http.StatusNotFound)
		return
	}

	_, err = w.Write(keyBytes)
	if err != nil {
		logger.Println("could not write private key bytes:", err.Error())
	}
}

func ApiOcspRequestHandler(w http.ResponseWriter, r *http.Request) {
	/*
		httpReq.Header.Add("Content-Type", "application/ocsp-request")
					httpReq.Header.Add("Accept", "application/ocsp-response")
					httpReq.Header.Add("Host", ocspUrl.Host)
	*/
	logger := logging.GetLogger()
	if r.Header.Get("Content-Type") != "application/ocsp-request" {
		logger.Println("incorrect content type header: " + r.Header.Get("Content-Type"))
		w.Write([]byte("Wrong Content-Type header: must be application/ocsp-request"))
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if r.Header.Get("Accept") != "application/ocsp-response" {
		logger.Println("incorrect Accept header: " + r.Header.Get("Accept"))
		w.Write([]byte("Wrong Content-Type header: must be application/ocsp-request"))
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	//if r.Header.Get("Host") == "" {
	//	log.Println("incorrect Host header: empty")
	//	w.Write([]byte("Wrong Host header: must not be empty"))
	//	w.WriteHeader(http.StatusBadRequest)
	//	return
	//}

	w.Header().Set("Content-Type", "application/ocsp-response")

	reqBody, err := ioutil.ReadAll(r.Body)
	if err != nil {
		logger.Println("could not read request body: " + err.Error())
		w.Write([]byte("could not read request body: " + err.Error()))
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	_ = r.Body.Close()
	ocspReq, err := ocsp.ParseRequest(reqBody)
	if err != nil {
		logger.Println("could not parse OCSP Request: " + err.Error())
		w.Write([]byte("could not parse OCSP Request: " + err.Error()))
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	logger.Println(ocspReq.SerialNumber)

	// hier prüfen, ob das Cert wirklich revoked ist
	// ...

	//ocspResp := ocsp.CreateResponse()
}
