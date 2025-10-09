package handler

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/KaiserWerk/CertMaker/internal/challenges"
	"github.com/KaiserWerk/CertMaker/internal/entity"
	"github.com/KaiserWerk/CertMaker/internal/global"
	"github.com/KaiserWerk/CertMaker/internal/helper"
	"github.com/KaiserWerk/CertMaker/internal/security"

	"github.com/gorilla/mux"
	"golang.org/x/crypto/ocsp"
)

// APIRequestCertificateWithSimpleRequestHandler handles a client's SimpleRequest,
// generates a new certificate and private key for the client and creates challenges, if enabled
func (bh *BaseHandler) APIRequestCertificateWithSimpleRequestHandler(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	var (
		logger = bh.ContextLogger("api")
		user   = r.Context().Value("user").(entity.User)
	)

	srMode := bh.DBSvc.GetSetting(global.SettingEnableSimpleRequestMode)
	if srMode != "true" {
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

	var certRequest entity.SimpleRequest
	err = json.Unmarshal(b.Bytes(), &certRequest)
	if err != nil {
		logger.Infof("error parsing certificate request: %s", err.Error())
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if certRequest.Days > global.CertificateMaxDays {
		certRequest.Days = global.CertificateMaxDays
	}
	if certRequest.Days < global.CertificateMinDays {
		certRequest.Days = global.CertificateMinDays
	}

	ri := entity.RequestInfo{
		CreatedFor:         user.ID,
		SimpleRequestBytes: b.Bytes(),
		Status:             "accepted",
	}
	if err = bh.DBSvc.AddRequestInfo(&ri); err != nil {
		logger.Infof("error inserting request info: %s\n", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// set up response
	response := entity.CertificateResponse{}

	var hasChallenge bool
	if httpChallengeEnabled := bh.DBSvc.GetSetting(global.SettingEnableHTTP01Challenge); httpChallengeEnabled == "true" {
		hasChallenge = true
		ch := &entity.Challenge{
			CreatedFor:    user.ID,
			RequestInfoID: ri.ID,
			PublicID:      fmt.Sprintf("%d-%s", user.ID, security.GenerateToken(20)),
			ChallengeType: "http-01",
			ValidUntil:    time.Now().Add(global.DefaultChallengeValidity),
		}
		if err = bh.DBSvc.AddChallenge(ch); err != nil {
			logger.Infof("error inserting challenge: %s\n", err.Error())
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		response.HTTP01Challenge = fmt.Sprintf(bh.Config.ServerHost+global.SolveHTTP01ChallengePath, ch.PublicID)
	}
	if dnsChallengeEnabled := bh.DBSvc.GetSetting(global.SettingEnableDNS01Challenge); dnsChallengeEnabled == "true" {
		hasChallenge = true
		ch := &entity.Challenge{
			CreatedFor:    user.ID,
			RequestInfoID: ri.ID,
			PublicID:      fmt.Sprintf("%d-%s", user.ID, security.GenerateToken(20)),
			ChallengeType: "dns-01",
			ValidUntil:    time.Now().Add(global.DefaultChallengeValidity),
		}
		if err = bh.DBSvc.AddChallenge(ch); err != nil {
			logger.Infof("error inserting challenge: %s\n", err.Error())
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		response.DNS01Challenge = fmt.Sprintf(bh.Config.ServerHost+global.SolvDNS01ChallengePath, ch.PublicID)
	}

	if hasChallenge {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		err = json.NewEncoder(w).Encode(response)
		if err != nil {
			logger.Infof("could not encode response: %s", err.Error())
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		return
	}

	certBytes, keyBytes, sn, err := bh.CertMaker.GenerateLeafCertAndKey(certRequest)
	if err != nil {
		logger.Errorf("error generating key + certificate: %s\n", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	ci := entity.CertInfo{
		SerialNumber:   sn,
		FromCSR:        false,
		CreatedForUser: user.ID,
		Revoked:        false,
	}

	if err = bh.DBSvc.AddCertInfo(&ci); err != nil {
		logger.Errorf("could not insert cert info into DB: %s", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	response.CertificatePem = string(certBytes)
	response.PrivateKeyPem = string(keyBytes)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)

	err = json.NewEncoder(w).Encode(response)
	if err != nil {
		logger.Infof("could not encode response: %s", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

// APIRequestCertificateWithCSRHandler handles a client's CSR for a new certificate,
// generates a new certificate for the client and creates challenges, if enabled
func (bh *BaseHandler) APIRequestCertificateWithCSRHandler(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	var (
		logger = bh.ContextLogger("api")
		err    error
		user   = r.Context().Value("user").(entity.User)
	)

	csrMode := bh.DBSvc.GetSetting(global.SettingEnableCSRRequestMode)
	if csrMode != "true" {
		w.WriteHeader(http.StatusNotImplemented)
		return
	}

	csrBytes, err := io.ReadAll(r.Body)
	if err != nil {
		logger.Debugf("could not read request body: %s", err.Error())
		http.Error(w, "malformed http request", http.StatusBadRequest)
		return
	}

	csr, err := x509.ParseCertificateRequest(csrBytes)
	if err != nil {
		logger.Debugf("could not parse certificate signing request: %s", err.Error())
		http.Error(w, "malformed certificate signing request", http.StatusBadRequest)
		return
	}

	u := r.Context().Value("user").(entity.User)

	ri := entity.RequestInfo{
		CreatedFor: u.ID,
		CsrBytes:   csrBytes,
		Status:     global.RequestInfoStatusAccepted,
	}

	if err = bh.DBSvc.AddRequestInfo(&ri); err != nil {
		logger.Infof("error inserting request info: %s\n", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	response := entity.CertificateResponse{}

	var hasChallenge bool
	if httpChallengeEnabled := bh.DBSvc.GetSetting(global.SettingEnableHTTP01Challenge); httpChallengeEnabled == "true" {
		hasChallenge = true
		ch := &entity.Challenge{
			CreatedFor:    user.ID,
			RequestInfoID: ri.ID,
			PublicID:      fmt.Sprintf("%d-%s", user.ID, security.GenerateToken(20)),
			ChallengeType: "http-01",
			ValidUntil:    time.Now().Add(global.DefaultChallengeValidity),
		}
		if err = bh.DBSvc.AddChallenge(ch); err != nil {
			logger.Infof("error inserting challenge: %s\n", err.Error())
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		response.HTTP01Challenge = fmt.Sprintf(bh.Config.ServerHost+global.SolveHTTP01ChallengePath, ch.PublicID)
	}
	if dnsChallengeEnabled := bh.DBSvc.GetSetting(global.SettingEnableDNS01Challenge); dnsChallengeEnabled == "true" {
		hasChallenge = true
		ch := &entity.Challenge{
			CreatedFor:    user.ID,
			RequestInfoID: ri.ID,
			PublicID:      fmt.Sprintf("%d-%s", user.ID, security.GenerateToken(20)),
			ChallengeType: "dns-01",
			ValidUntil:    time.Now().Add(global.DefaultChallengeValidity),
		}
		if err = bh.DBSvc.AddChallenge(ch); err != nil {
			logger.Infof("error inserting challenge: %s\n", err.Error())
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		response.DNS01Challenge = fmt.Sprintf(bh.Config.ServerHost+global.SolvDNS01ChallengePath, ch.PublicID)
	}

	if hasChallenge {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		err = json.NewEncoder(w).Encode(response)
		if err != nil {
			logger.Infof("could not encode response: %s", err.Error())
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		return
	}

	certBytes, sn, err := bh.CertMaker.GenerateCertificateByCSR(csr)
	if err != nil {
		logger.Errorf("error generating certificate: %s\n", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	ci := &entity.CertInfo{
		SerialNumber:   sn,
		FromCSR:        true,
		CreatedForUser: user.ID,
		Revoked:        false,
	}
	err = bh.DBSvc.AddCertInfo(ci)
	if err != nil {
		logger.Errorf("could not insert cert info into DB: %s", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	response.CertificatePem = string(certBytes)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)

	err = json.NewEncoder(w).Encode(response)
	if err != nil {
		logger.Infof("could not encode response: %s", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

// APIObtainCertificateHandler allows to actually download a certificate
func (bh *BaseHandler) APIObtainCertificateHandler(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	var (
		logger = bh.ContextLogger("api")
		id     = mux.Vars(r)["id"]
	)

	certID, err := strconv.ParseInt(id, 10, 64)
	if err != nil {
		logger.Debugf("ID is not numeric: %s", id)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	certBytes, err := bh.CertMaker.FindLeafCertificate(certID)
	if err != nil {
		logger.Debugf("No certificate found for ID %s", id)
		w.WriteHeader(http.StatusNotFound)
		return
	}

	//w.Header().Set("Content-Disposition", "attachment; filename=\""+id+"-cert.pem\"")
	w.Header().Set("Content-Type", global.PEMContentType)
	_, err = w.Write(certBytes)
	if err != nil {
		logger.Error("could not write cert bytes: " + err.Error())
	}
}

// APIObtainPrivateKeyHandler allows to actually download a private key
func (bh *BaseHandler) APIObtainPrivateKeyHandler(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	var (
		logger = bh.ContextLogger("api")
		vars   = mux.Vars(r)
		id     = vars["id"]
	)

	keyID, err := strconv.ParseInt(id, 10, 64)
	if err != nil {
		logger.Debugf("ID is not numeric: %s", id)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	keyBytes, err := bh.CertMaker.FindLeafPrivateKey(keyID)
	if err != nil {
		logger.Debugf("No private key found for ID %s", id)
		w.WriteHeader(http.StatusNotFound)
		return
	}

	//w.Header().Set("Content-Disposition", "attachment; filename=\""+id+"-key.pem\"")
	w.Header().Set("Content-Type", global.PEMContentType)
	_, err = w.Write(keyBytes)
	if err != nil {
		logger.Error("could not write private key bytes: " + err.Error())
	}
}

// APIOSCPRequestHandler responds to OCSP requests with whether the certificate
// in question is revoked or not
func (bh *BaseHandler) APIOSCPRequestHandler(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	var (
		err    error
		logger = bh.ContextLogger("api")
		vars   = mux.Vars(r)
	)

	if r.Header.Get("Content-Type") != "application/ocsp-request" {
		logger.Debug("incorrect content type header: " + r.Header.Get("Content-Type"))
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	//if r.Header.Get("Accept") != "application/ocsp-response" {
	//	logger.Debug("incorrect Accept header: " + r.Header.Get("Accept"))
	//	w.WriteHeader(http.StatusBadRequest)
	//	return
	//}

	//if r.Header.Get("Host") == "" {
	//	logger.Debug("incorrect Host header: empty")
	//	w.WriteHeader(http.StatusBadRequest)
	//	return
	//}

	w.Header().Set("Content-Type", "application/ocsp-response")

	b64 := vars["base64"]

	var request []byte
	switch r.Method {
	case http.MethodPost:
		logger.Debug("POST request")
		request, err = io.ReadAll(r.Body)
		if err != nil {
			logger.Debugf("could not read request body: %s", err.Error())
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		_ = r.Body.Close()
	case http.MethodGet:
		logger.Debug("GET request")
		request, err = base64.StdEncoding.DecodeString(b64)
		if err != nil {
			logger.Debugf("could not base64 decode: %s", err.Error())
			w.WriteHeader(http.StatusBadRequest)
			return
		}
	}

	ocspReq, err := ocsp.ParseRequest(request)
	if err != nil {
		logger.Debug("could not parse OCSP Request: " + err.Error())
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	status := ocsp.Good
	ci, err := bh.DBSvc.FindCertInfo("serial_number = ?", ocspReq.SerialNumber.Int64()) // geht das?
	if err != nil {
		logger.Debug("could not find cert info: " + err.Error())
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if ci.Revoked {
		status = ocsp.Revoked
	}

	certContent, err := os.ReadFile(filepath.Join(bh.Config.DataDir, "leafcerts", fmt.Sprintf("%d-cert.pem", ci.SerialNumber)))
	if err != nil {
		logger.Debug("could not read certificate file: " + err.Error())
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	block, _ := pem.Decode(certContent)
	if block == nil {
		logger.Debug("could not decode PEM block")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		logger.Debug("could not parse certificate: " + err.Error())
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	revokedAt := time.Now()
	if ci.Revoked && ci.RevokedAt.Valid {
		revokedAt = ci.RevokedAt.Time
	}
	responseTemplate := ocsp.Response{
		Status:       status,
		SerialNumber: ocspReq.SerialNumber,
		ThisUpdate:   time.Now().AddDate(0, 0, -1).UTC(),
		//adding 1 day after the current date. This ocsp library sets the default date to epoch which makes ocsp clients freak out.
		NextUpdate:         time.Now().AddDate(0, 0, 1).UTC(),
		RevokedAt:          revokedAt,
		RevocationReason:   ocsp.Unspecified,
		Certificate:        cert,
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		IssuerHash:         crypto.SHA512,
	}

	rootCert, rootKey, err := bh.CertMaker.GetRootKeyPair()
	if err != nil {
		logger.Errorf("could not retrieve root certificate: %s", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	resp, err := ocsp.CreateResponse(rootCert, rootCert, responseTemplate, rootKey)
	if err != nil {
		logger.Errorf("could not create and sign OCSP response: %s", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Write(resp)
}

// APISolveHTTP01ChallengeHandler handles solving the challenges created for certificate request
func (bh *BaseHandler) APISolveHTTP01ChallengeHandler(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	var (
		logger = bh.ContextLogger("api")
		vars   = mux.Vars(r)
	)

	var request entity.HTTP01ChallengeRequest
	err := json.NewDecoder(r.Body).Decode(&request)
	if err != nil {
		logger.Errorf("could not decode request body: %s", err.Error())
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	var response entity.CertificateResponse

	// fetch challenge info from DB
	challenge, err := bh.DBSvc.FindChallenge("public_id = ?", vars["challengeID"])
	if err != nil {
		if err == sql.ErrNoRows {
			logger.Debugf("no challenge found for public ID %s", vars["challengeID"])
			w.WriteHeader(http.StatusNotFound)
			return
		}
		logger.Errorf("could not query challenge: %s", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// check if challenge type matches
	if challenge.ChallengeType != "http-01" {
		logger.Debugf("challenge type is not http-01: %s", challenge.ChallengeType)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// get requestInfo for challenge
	requestInfo, err := bh.DBSvc.GetRequestInfo(challenge.RequestInfoID)
	if err != nil {
		logger.Errorf("could not get request info for ID %v: %s", challenge.RequestInfoID, err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	var (
		domains, ips  []string
		fromCSR       = requestInfo.CsrBytes != nil
		csr           *x509.CertificateRequest
		simpleRequest entity.SimpleRequest
	)

	if fromCSR {
		// determine DNS names and IPs from CSR
		csr, err = x509.ParseCertificateRequest(requestInfo.CsrBytes)
		if err != nil {
			logger.Errorf("could not parse CSR: %s", err.Error())
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		domains = append(domains, csr.DNSNames...)
		for _, ip := range csr.IPAddresses {
			ips = append(ips, ip.To4().String())
		}
	} else {
		err = json.Unmarshal(requestInfo.SimpleRequestBytes, &simpleRequest)
		if err != nil {
			logger.Errorf("could not unmarshal simple request: %s", err.Error())
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		domains = simpleRequest.Domains
		ips = simpleRequest.IPs
	}

	// check well-known path for every domain
	for _, domain := range domains {
		if domain == "" {
			continue
		}

		if helper.StringSliceContains(global.DNSNamesToSkip, domain) {
			continue
		}

		ok, err := challenges.CheckHTTP01Challenge(bh.Client, domain, request.ChallengePort, challenge.Token)
		if err != nil {
			response.Error = fmt.Sprintf("error checking domain %s: %s", domain, err.Error())
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(response)
			return
		}

		if !ok {
			response.Error = fmt.Sprintf("HTTP response from domain %s did not respond with expected token", domain)
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(response)
			return
		}
	}

	// check well known path for every IP
	for _, ip := range ips {
		ok, err := challenges.CheckHTTP01Challenge(bh.Client, ip, request.ChallengePort, challenge.Token)
		if err != nil {
			response.Error = fmt.Sprintf("error checking IP %s: %s", ip, err.Error())
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(response)
			return
		}

		if !ok {
			response.Error = fmt.Sprintf("HTTP response from IP %s did not respond with expected token", ip)
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(response)
			return
		}
	}

	// from here on, we know that the challenge was successful for all domains and IPs
	// that means we can issue the certificate

	var (
		certBytes, keyBytes []byte
		sn                  int64
	)
	if fromCSR {
		// issue certificate from CSR
		certBytes, sn, err = bh.CertMaker.GenerateCertificateByCSR(csr)
		if err != nil {
			logger.Errorf("error generating certificate from CSR: %s\n", err.Error())
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	} else {
		certBytes, keyBytes, sn, err = bh.CertMaker.GenerateLeafCertAndKey(simpleRequest)
		if err != nil {
			logger.Errorf("error generating key + certificate: %s\n", err.Error())
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	}

	// update the request info status to "issued"
	requestInfo.Status = "issued"
	err = bh.DBSvc.UpdateRequestInfo(requestInfo)
	if err != nil {
		logger.Errorf("could not update request info status: %s", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// store certificate info in DB
	ci := entity.CertInfo{
		SerialNumber:   sn,
		FromCSR:        fromCSR,
		CreatedForUser: challenge.CreatedFor,
		Revoked:        false,
	}

	err = bh.DBSvc.AddCertInfo(&ci)
	if err != nil {
		logger.Errorf("could not insert cert info into DB: %s", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// set up response
	response.CertificatePem = string(certBytes)
	if !fromCSR {
		response.PrivateKeyPem = string(keyBytes)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	err = json.NewEncoder(w).Encode(response)
	if err != nil {
		logger.Infof("could not encode response: %s", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

func (bh *BaseHandler) APISolveDNS01ChallengeHandler(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	var (
		logger = bh.ContextLogger("api")
		vars   = mux.Vars(r)
	)

	var response entity.CertificateResponse

	// fetch challenge info from DB
	challenge, err := bh.DBSvc.FindChallenge("public_id = ?", vars["challengeID"])
	if err != nil {
		if err == sql.ErrNoRows {
			logger.Debugf("no challenge found for public ID %s", vars["challengeID"])
			w.WriteHeader(http.StatusNotFound)
			return
		}
		logger.Errorf("could not query challenge: %s", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// check if challenge type matches
	if challenge.ChallengeType != "dns-01" {
		logger.Debugf("challenge type is not dns-01: %s", challenge.ChallengeType)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// get requestInfo for challenge
	requestInfo, err := bh.DBSvc.GetRequestInfo(challenge.RequestInfoID)
	if err != nil {
		logger.Errorf("could not get request info for ID %v: %s", challenge.RequestInfoID, err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	var (
		domains       []string
		fromCSR       = requestInfo.CsrBytes != nil
		csr           *x509.CertificateRequest
		simpleRequest entity.SimpleRequest
	)

	if fromCSR {
		// determine DNS names and IPs from CSR
		csr, err = x509.ParseCertificateRequest(requestInfo.CsrBytes)
		if err != nil {
			logger.Errorf("could not parse CSR: %s", err.Error())
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		domains = append(domains, csr.DNSNames...)
	} else {
		err = json.Unmarshal(requestInfo.SimpleRequestBytes, &simpleRequest)
		if err != nil {
			logger.Errorf("could not unmarshal simple request: %s", err.Error())
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		domains = simpleRequest.Domains
	}

	// check well known path for every domain
	for _, domain := range domains {
		if domain == "" {
			continue
		}

		if helper.StringSliceContains(global.DNSNamesToSkip, domain) {
			continue
		}

		ok, err := challenges.CheckDNS01Challenge(domain, challenge.Token)
		if err != nil {
			response.Error = fmt.Sprintf("error checking domain %s: %s", domain, err.Error())
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(response)
			return
		}

		if !ok {
			response.Error = fmt.Sprintf("DNS check of TXT record for %s%s did not match expected token", global.DNS01ChallengeSubdomain, domain)
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(response)
			return
		}
	}

	// from here on, we know that the challenge was successful for all domains
	// that means we can issue the certificate

	var (
		certBytes, keyBytes []byte
		sn                  int64
	)
	if fromCSR {
		// issue certificate from CSR
		certBytes, sn, err = bh.CertMaker.GenerateCertificateByCSR(csr)
		if err != nil {
			logger.Errorf("error generating certificate from CSR: %s\n", err.Error())
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	} else {
		certBytes, keyBytes, sn, err = bh.CertMaker.GenerateLeafCertAndKey(simpleRequest)
		if err != nil {
			logger.Errorf("error generating key + certificate: %s\n", err.Error())
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	}

	// update the request info status to "issued"
	requestInfo.Status = "issued"
	err = bh.DBSvc.UpdateRequestInfo(requestInfo)
	if err != nil {
		logger.Errorf("could not update request info status: %s", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// store certificate info in DB
	ci := entity.CertInfo{
		SerialNumber:   sn,
		FromCSR:        fromCSR,
		CreatedForUser: challenge.CreatedFor,
		Revoked:        false,
	}

	err = bh.DBSvc.AddCertInfo(&ci)
	if err != nil {
		logger.Errorf("could not insert cert info into DB: %s", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// set up response
	response.CertificatePem = string(certBytes)
	if !fromCSR {
		response.PrivateKeyPem = string(keyBytes)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	err = json.NewEncoder(w).Encode(response)
	if err != nil {
		logger.Infof("could not encode response: %s", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

// APIRootCertificateDownloadHandler allows to programmatically obtain the root certificate
func (bh *BaseHandler) APIRootCertificateDownloadHandler(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	logger := bh.ContextLogger("api")

	certFile := filepath.Join(bh.Config.DataDir, global.RootCertificateFilename)
	fh, err := os.Open(certFile)
	if err != nil {
		logger.WithField("error", err.Error()).Error("could not open root cert file for reading")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", global.PEMContentType)
	_, err = io.Copy(w, fh)
	if err != nil {
		logger.WithField("error", err.Error()).Error("could not write root cert contents")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	_ = fh.Close()
}

// APIRevokeCertificateHandler allows a user to revoke a certificate by its serial number
func (bh *BaseHandler) APIRevokeCertificateHandler(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	var (
		logger = bh.ContextLogger("api")
		u      = r.Context().Value("user").(entity.User)
		vars   = mux.Vars(r)
	)

	ci, err := bh.DBSvc.FindCertInfo("serial_number = ?", vars["sn"])
	if err != nil {
		logger.Debugf("could not find certinfo: %s", err.Error())
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if ci.CreatedForUser != u.ID && !u.Admin {
		logger.Debugf("this is not your certificate")
		w.WriteHeader(http.StatusForbidden)
		return
	}

	if ci.Revoked {
		logger.Debugf("certificate is already revoked")
		w.WriteHeader(http.StatusGone)
		return
	}

	ci.Revoked = true
	ci.RevokedAt = sql.NullTime{Time: time.Now(), Valid: true}

	err = bh.DBSvc.UpdateCertInfo(&ci)
	if err != nil {
		logger.Debugf("could not update certinfo: %s", err.Error())
		w.WriteHeader(http.StatusBadRequest)
		return
	}
}
