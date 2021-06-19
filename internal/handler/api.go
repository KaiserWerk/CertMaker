package handler

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/KaiserWerk/CertMaker/internal/certmaker"
	"github.com/KaiserWerk/CertMaker/internal/dbservice"
	"github.com/KaiserWerk/CertMaker/internal/entity"
	"github.com/KaiserWerk/CertMaker/internal/global"
	"github.com/KaiserWerk/CertMaker/internal/helper"
	"github.com/KaiserWerk/CertMaker/internal/logging"
	"github.com/KaiserWerk/CertMaker/internal/security"
	"github.com/gorilla/mux"
	"golang.org/x/crypto/ocsp"
	"io"
	"io/ioutil"
	"net/http"
	"strconv"
)

// ApiRequestCertificateHandler handles a client's request,
// generates a new certificate and private key for the client and sets appropriate
// location headers
func ApiRequestCertificateHandler(w http.ResponseWriter, r *http.Request) {
	var (
		ds          = dbservice.New()
		config      = global.GetConfiguration()
		logger      = logging.GetLogger().WithField("function", "handler.ApiRequestCertificateHandler")
		certRequest entity.SimpleRequest
	)

	simpleMode := ds.GetSetting("certificate_request_simple_mode")
	if simpleMode != "true" {
		logger.Debug("simple mode is not enabled")
		w.WriteHeader(http.StatusNotImplemented)
		return
	}

	var b bytes.Buffer
	_, err := io.Copy(&b, r.Body)
	if err != nil {
		logger.Infof("could not read request body: %s", err.Error())
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	err = json.Unmarshal(b.Bytes(), &certRequest)
	if err != nil {
		logger.Infof("error parsing certificate request: %s", err.Error())
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	defer r.Body.Close()

	if certRequest.Days > global.CertificateMaxDays {
		certRequest.Days = global.CertificateMaxDays
	}
	if certRequest.Days < global.CertificateMinDays {
		certRequest.Days = global.CertificateMinDays
	}

	if dnsValidate := ds.GetSetting("certificate_request_require_domain_ownership"); dnsValidate == "true" {
		token, err := security.GenerateToken(global.ChallengeTokenLength)
		if err != nil {
			logger.Infof("error generating token: %s\n", err.Error())
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		ri := entity.RequestInfo{
			SimpleRequestBytes: b.Bytes(),
			Token:              token,
			Status:             "accepted",
		}

		if err = ds.AddRequestInfo(&ri); err != nil {
			logger.Infof("error inserting request info: %s\n", err.Error())
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "text/plain; charset=utf8")
		w.Header().Set(global.ChallengeLocationHeader, fmt.Sprintf(config.ServerHost+global.SolveChallengePath, ri.ID))
		w.WriteHeader(http.StatusAccepted)
		_, _ = io.WriteString(w, token)

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

	if err = ds.AddCertInfo(&ci); err != nil {
		logger.Errorf("could not insert cert info into DB: %s", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Add(global.CertificateLocationHeader, fmt.Sprintf("%s/api/certificate/%d/obtain", config.ServerHost, sn))
	w.Header().Add(global.PrivateKeyLocationHandler, fmt.Sprintf("%s/api/privatekey/%d/obtain", config.ServerHost, sn))
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

	if dnsValidate := ds.GetSetting("certificate_request_require_domain_ownership"); dnsValidate == "true" {
		token, err := security.GenerateToken(global.ChallengeTokenLength)
		if err != nil {
			logger.Infof("error generating token: %s\n", err.Error())
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		ri := entity.RequestInfo{
			CsrBytes: csrBytes,
			Token:    token,
			Status:   "accepted",
		}

		if err = ds.AddRequestInfo(&ri); err != nil {
			logger.Infof("error inserting request info: %s\n", err.Error())
			w.WriteHeader(http.StatusInternalServerError)
			return
		}


		w.Header().Set("Content-Type", "text/plain; charset=utf8")
		w.Header().Set(global.ChallengeLocationHeader, fmt.Sprintf(config.ServerHost+global.SolveChallengePath, ri.ID))
		w.WriteHeader(http.StatusAccepted)
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

	w.Header().Add(global.CertificateLocationHeader, fmt.Sprintf("%s/api/certificate/%d/obtain", config.ServerHost, sn))
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

	//w.Header().Set("Content-Disposition", "attachment; filename=\""+id+"-cert.pem\"")
	w.Header().Set("Content-Type", "text/plain; charset=utf8")
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

	//w.Header().Set("Content-Disposition", "attachment; filename=\""+id+"-key.pem\"")
	w.Header().Set("Content-Type", "text/plain; charset=utf8")
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
		vars   = mux.Vars(r)
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

func ApiSolveChallengeHandler(w http.ResponseWriter, r *http.Request) {
	var (
		logger             = logging.GetLogger().WithField("function", "handler.ApiSolveChallengeHandler")
		config             = global.GetConfiguration()
		client             = global.GetClient()
		ds                 = dbservice.New()
		vars               = mux.Vars(r)
		b                  bytes.Buffer
		validationPort     string
		fromCsr            bool
		certificateRequest entity.SimpleRequest
		csr                x509.CertificateRequest
	)

	validationPort = r.Header.Get("X-Validation-Port")
	if validationPort == "" {
		validationPort = "80"
	}

	_, err := strconv.Atoi(validationPort)
	if err != nil {
		logger.Debug("Port header has non-numeric value")
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	ri, err := ds.GetRequestInfo(vars["id"])
	if err != nil {
		logger.Debugf("could not get request info for ID %v", vars["id"])
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if ri.SimpleRequestBytes != nil {
		err = json.Unmarshal(ri.SimpleRequestBytes, &certificateRequest)
		if err != nil {
			logger.Errorf("could not unmarshal certificate request: %s", err.Error())
			return
		}
		fromCsr = false
	} else if ri.CsrBytes != nil {
		err = json.Unmarshal(ri.CsrBytes, &csr)
		if err != nil {
			logger.Errorf("could not unmarshal csr: %s", err.Error())
			return
		}
		fromCsr = true
	}

	// Domain validation
	var domains []string
	if !fromCsr {
		domains = certificateRequest.Domains
	} else {
		domains = csr.DNSNames
	}
	for _, domain := range domains {
		// skip local dns names, like localhost or 127.0.0.1
		if helper.StringSliceContains(global.DnsNamesToSkip, domain) {
			continue
		}

		attempts := []string{
			fmt.Sprintf("https://%s:%s%s", domain, validationPort, global.WellKnownPath),
			fmt.Sprintf("http://%s:%s%s", domain, validationPort, global.WellKnownPath),
		}

		for _, attempt := range attempts {
			req, err := http.NewRequest(http.MethodGet, attempt, nil)
			if err != nil {
				logger.Debugf("could not create request: " + err.Error())
				continue
			}

			resp, err := client.Do(req)
			if err != nil {
				logger.Debugf("could not execute request for HTTPS attempt: " + err.Error())
				continue
			}
			_, err = io.Copy(&b, resp.Body)
			if err != nil {
				logger.Debugf("could not read request body from HTTPS attempt: " + err.Error())
				continue
			}
			_ = resp.Body.Close()

			// TODO check if RI is from correct user

			if b.String() != ri.Token {
				logger.Debugf("invalid token")
				w.WriteHeader(http.StatusForbidden)
				return
			}
		}
	}

	// IP validation
	ips := make([]string, 0)
	if !fromCsr {
		ips = certificateRequest.IPs
	} else {
		for _, v := range csr.IPAddresses {
			ips = append(ips, v.String())
		}

	}
	for _, ip := range ips {
		// skip local dns names, like localhost or 127.0.0.1
		if helper.StringSliceContains(global.DnsNamesToSkip, ip) {
			continue
		}

		attempts := []string{
			fmt.Sprintf("https://%s:%s%s", ip, validationPort, global.WellKnownPath),
			fmt.Sprintf("http://%s:%s%s", ip, validationPort, global.WellKnownPath),
		}

		for _, attempt := range attempts {
			req, err := http.NewRequest(http.MethodGet, attempt, nil)
			if err != nil {
				logger.Debugf("could not create request: " + err.Error())
				continue
			}

			resp, err := client.Do(req)
			if err != nil {
				logger.Debugf("could not execute request for HTTPS attempt: " + err.Error())
				continue
			}
			_, err = io.Copy(&b, resp.Body)
			if err != nil {
				logger.Debugf("could not read request body from HTTPS attempt: " + err.Error())
				continue
			}
			_ = resp.Body.Close()

			// TODO check if RI is from correct user

			if b.String() != ri.Token {
				logger.Debugf("invalid token")
				w.WriteHeader(http.StatusForbidden)
				return
			}
		}
	}

	logger.Debug("successfully validated")

	var sn int64
	if !fromCsr {
		sn, err = certmaker.GenerateLeafCertAndKey(certificateRequest)
		if err != nil {
			logger.Errorf("error generating key + certificate: %s\n", err.Error())
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	} else {
		sn, err = certmaker.GenerateCertificateByCSR(&csr)
		if err != nil {
			logger.Errorf("error generating key + certificate: %s\n", err.Error())
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	}

	userFromContext := r.Context().Value("user")
	u := userFromContext.(entity.User)

	ci := entity.CertInfo{
		SerialNumber:   sn,
		FromCSR:        fromCsr,
		CreatedForUser: u.ID,
		Revoked:        false,
		RevokedBecause: "",
	}

	if err = ds.AddCertInfo(&ci); err != nil {
		logger.Errorf("could not insert cert info into DB: %s", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	ri.Status = "finished"
	err = ds.UpdateRequestInfo(&ri)
	if err != nil {
		logger.Errorf("could not update request info: %s", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Add(global.CertificateLocationHeader, fmt.Sprintf("%s/api/certificate/%d/obtain", config.ServerHost, sn))
	if !fromCsr {
		w.Header().Add(global.PrivateKeyLocationHandler, fmt.Sprintf("%s/api/privatekey/%d/obtain", config.ServerHost, sn))
	}
}

