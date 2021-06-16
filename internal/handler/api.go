package handler

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/KaiserWerk/CertMaker/internal/certmaker"
	"github.com/KaiserWerk/CertMaker/internal/dbservice"
	"github.com/KaiserWerk/CertMaker/internal/entity"
	"github.com/KaiserWerk/CertMaker/internal/global"
	"github.com/KaiserWerk/CertMaker/internal/logging"
	"github.com/KaiserWerk/CertMaker/internal/security"
	"github.com/gorilla/mux"
	"golang.org/x/crypto/ocsp"
	"io/ioutil"
	"net/http"
	"strings"
)

// ApiRequestCertificateHandler handles a client's request,
// generates a new certificate and private key for the client and sets appropriate
// location headers
func ApiRequestCertificateHandler(w http.ResponseWriter, r *http.Request) {
	var (
		ds          = dbservice.New()
		config      = global.GetConfiguration()
		logger      = logging.GetLogger().WithField("function", "handler.ApiRequestCertificateHandler")
		certRequest entity.CertificateRequest
	)

	simpleMode := ds.GetSetting("certificate_request_simple_mode")
	if simpleMode != "true" {
		logger.Debug("simple mode is not enabled")
		w.WriteHeader(http.StatusNotImplemented)
		return
	}

	err := json.NewDecoder(r.Body).Decode(&certRequest)
	if err != nil {
		logger.Infof("error parsing certificate request: %s\n", err.Error())
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	_ = r.Body.Close()

	dnsValidate := ds.GetSetting("certificate_request_require_domain_ownership")
	if dnsValidate == "true" {
		// create challenge and return token
		token, err := security.GenerateToken(global.ChallengeTokenLength)
		if err != nil {
			logger.Infof("error generating token: %s\n", err.Error())
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		ri := entity.RequestInfo{
			FromCSR:        false,
			Domains:        strings.Join(certRequest.Domains, ","),
			IpAddresses:    strings.Join(certRequest.IPs, ","),
			EmailAddresses: strings.Join(certRequest.EmailAddresses, ","),
			Days:           certRequest.Days,
			Token:          token,
			Status:         "accepted",
		}

		err = ds.AddRequestInfo(&ri)
		if err != nil {
			logger.Infof("error inserting request info: %s\n", err.Error())
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusAccepted)
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, token)

		return
	}

	sn, err := certmaker.GenerateLeafCertAndKey(certRequest)
	if err != nil {
		logger.Errorf("error generating key + certificate: %s\n", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	userFromContext := r.Context().Value("user")
	u := userFromContext.(entity.User)

	ci := entity.CertInfo{
		SerialNumber:   sn,
		FromCSR:        false,
		CreatedForUser: u.ID,
		Revoked:        false,
		RevokedBecause: "",
	}
	err = ds.AddCertInfo(&ci)
	if err != nil {
		logger.Errorf("could not insert cert info into DB: %s", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Add("X-Certificate-Location", fmt.Sprintf("%s/api/certificate/%d/obtain", config.ServerHost, sn))
	w.Header().Add("X-Privatekey-Location", fmt.Sprintf("%s/api/privatekey/%d/obtain", config.ServerHost, sn))
}

// ApiRequestCertificateWithCSRHandler handles a client's request for a new certificate,
// generates a new certificate for the client and sets appropriate location headers
func ApiRequestCertificateWithCSRHandler(w http.ResponseWriter, r *http.Request) {
	var (
		logger = logging.GetLogger().WithField("function", "handler.ApiRequestCertificateWithCSRHandler")
		ds     = dbservice.New()
		err    error
		config = global.GetConfiguration()
	)

	normalMode := ds.GetSetting("certificate_request_normal_mode")
	if normalMode != "true" {
		logger.Debug("normal mode is not enabled")
		w.WriteHeader(http.StatusNotImplemented)
		return
	}

	csrBytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		logger.Debugf("could not read request body: %s", err.Error())
		http.Error(w, "malformed http request", http.StatusBadRequest)
		return
	}
	_ = r.Body.Close()

	p, _ := pem.Decode(csrBytes)

	csr, err := x509.ParseCertificateRequest(p.Bytes)
	if err != nil {
		logger.Debugf("could not parse certificate singing request: %s", err.Error())
		http.Error(w, "malformed certificate singing request", http.StatusBadRequest)
		return
	}

	// if domain/ip validation is enabled, generate a token the requester
	// must place to be available from a special url.
	// /.well-known/certmaker-challenge/token.txt
	dnsValidate := ds.GetSetting("certificate_request_require_domain_ownership")
	if dnsValidate == "true" {
		token, err := security.GenerateToken(global.ChallengeTokenLength)
		if err != nil {
			logger.Infof("error generating token: %s\n", err.Error())
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		ips := make([]string, 0)
		for _, v := range csr.IPAddresses {
			ips = append(ips, v.String())
		}
		ri := entity.RequestInfo{
			FromCSR:        true,
			Domains:        strings.Join(csr.DNSNames, ","),
			IpAddresses:    strings.Join(ips, ","),
			EmailAddresses: strings.Join(csr.EmailAddresses, ","),
			Days:           global.CertificateDefaultDays,
			Token:          token,
			Status:         "accepted",
		}

		err = ds.AddRequestInfo(&ri)
		if err != nil {
			logger.Infof("error inserting request info: %s\n", err.Error())
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusAccepted)
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, token)

		return
	}

	sn, err := certmaker.GenerateCertificateByCSR(csr)
	if err != nil {
		logger.Errorf("error generating certificate: %s\n", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	userFromContext := r.Context().Value("user")
	u := userFromContext.(entity.User)

	ci := entity.CertInfo{
		SerialNumber:   sn,
		FromCSR:        true,
		CreatedForUser: u.ID,
		Revoked:        false,
		RevokedBecause: "",
	}
	err = ds.AddCertInfo(&ci)
	if err != nil {
		logger.Errorf("could not insert cert info into DB: %s", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Add("X-Certificate-Location", fmt.Sprintf("%s/api/certificate/%d/obtain", config.ServerHost, sn))
}

// ApiObtainCertificateHandler allows to actually download a certificate
func ApiObtainCertificateHandler(w http.ResponseWriter, r *http.Request) {
	var (
		logger = logging.GetLogger().WithField("function", "handler.ApiObtainCertificateHandler")
		vars   = mux.Vars(r)
		id     = vars["id"]
	)

	certBytes, err := certmaker.FindLeafCertificate(id)
	if err != nil {
		logger.Debugf("No certificate found for ID %s", id)
		w.WriteHeader(http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Disposition", "attachment; filename=\""+id+"-cert.pem\"")
	_, err = w.Write(certBytes)
	if err != nil {
		logger.Error("could not write cert bytes: " + err.Error())
	}
}

// ApiObtainPrivateKeyHandler allows to actually download a private key
func ApiObtainPrivateKeyHandler(w http.ResponseWriter, r *http.Request) {
	var (
		logger = logging.GetLogger().WithField("function", "handler.ApiObtainPrivateKeyHandler")
		vars   = mux.Vars(r)
		id     = vars["id"]
	)

	keyBytes, err := certmaker.FindLeafPrivateKey(id)
	if err != nil {
		logger.Debugf("No private key found for ID %s", id)
		w.WriteHeader(http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Disposition", "attachment; filename=\""+id+"-key.pem\"")
	_, err = w.Write(keyBytes)
	if err != nil {
		logger.Error("could not write private key bytes: " + err.Error())
	}
}

// ApiOcspRequestHandler responds to OCSP requests with whether the certificate
// in question is revoked or not
func ApiOcspRequestHandler(w http.ResponseWriter, r *http.Request) {
	/*
		httpReq.Header.Add("Content-Type", "application/ocsp-request")
					httpReq.Header.Add("Accept", "application/ocsp-response")
					httpReq.Header.Add("Host", ocspUrl.Host)
	*/
	var (
		logger = logging.GetLogger().WithField("function", "handler.ApiOcspRequestHandler")
		vars = mux.Vars(r)
	)
	if r.Header.Get("Content-Type") != "application/ocsp-request" {
		logger.Debug("incorrect content type header: " + r.Header.Get("Content-Type"))
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if r.Header.Get("Accept") != "application/ocsp-response" {
		logger.Debug("incorrect Accept header: " + r.Header.Get("Accept"))
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	//if r.Header.Get("Host") == "" {
	//	logger.Debug("incorrect Host header: empty")
	//	w.WriteHeader(http.StatusBadRequest)
	//	return
	//}

	b64 := vars["base64"]

	w.Header().Set("Content-Type", "application/ocsp-response")

	reqBody, err := ioutil.ReadAll(r.Body)
	if err != nil {
		logger.Debug("could not read request body: " + err.Error())
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	logger.Debugf("Request body length: %d", len(reqBody))

	b64dec, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		logger.Debug("could not decode base64 request variable: " + err.Error())
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	_ = r.Body.Close()
	ocspReq, err := ocsp.ParseRequest(b64dec)
	if err != nil {
		logger.Debug("could not parse OCSP Request: " + err.Error())
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	logger.Debug(ocspReq.SerialNumber)

	// hier prüfen, ob das Cert wirklich revoked ist
	// ...

	//ocspResp := ocsp.CreateResponse()
}
