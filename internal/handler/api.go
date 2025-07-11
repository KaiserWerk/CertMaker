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
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/KaiserWerk/CertMaker/internal/entity"
	"github.com/KaiserWerk/CertMaker/internal/global"
	"github.com/KaiserWerk/CertMaker/internal/helper"
	"github.com/KaiserWerk/CertMaker/internal/security"

	"github.com/gorilla/mux"
	"golang.org/x/crypto/ocsp"
)

// ApiRequestCertificateHandler handles a client's request,
// generates a new certificate and private key for the client and sets appropriate
// location headers or creates a challenge
func (bh *BaseHandler) ApiRequestCertificateHandler(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	if r.Context().Value("user") == nil {
		bh.ContextLogger("api").Debug("user not found in context")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	var (
		logger = bh.ContextLogger("api")
		user   = r.Context().Value("user").(entity.User)
	)

	simpleMode := bh.DBSvc.GetSetting("certificate_request_simple_mode")
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

	if dnsValidate := bh.DBSvc.GetSetting("certificate_request_require_domain_ownership"); dnsValidate == "true" {
		token, err := security.GenerateToken(global.ChallengeTokenLength)
		if err != nil {
			logger.Infof("error generating token: %s\n", err.Error())
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		ri := entity.RequestInfo{
			CreatedFor:         user.ID,
			SimpleRequestBytes: b.Bytes(),
			Token:              token,
			Status:             "accepted",
		}

		if err = bh.DBSvc.AddRequestInfo(&ri); err != nil {
			logger.Infof("error inserting request info: %s\n", err.Error())
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set(global.ChallengeLocationHeader, fmt.Sprintf(bh.Config.ServerHost+global.SolveChallengePath, ri.ID))
		w.WriteHeader(http.StatusAccepted)
		_, _ = io.WriteString(w, token)

		return
	}

	sn, err := bh.CM.GenerateLeafCertAndKey(certRequest)
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

	w.Header().Add(global.CertificateLocationHeader, fmt.Sprintf(bh.Config.ServerHost+global.CertificateObtainPath, sn))
	w.Header().Add(global.PrivateKeyLocationHandler, fmt.Sprintf(bh.Config.ServerHost+global.PrivateKeyObtainPath, sn))
}

// ApiRequestCertificateWithCSRHandler handles a client's request for a new certificate,
// generates a new certificate for the client and sets appropriate location headers
// or creates a challenge
func (bh *BaseHandler) ApiRequestCertificateWithCSRHandler(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	if r.Context().Value("user") == nil {
		bh.ContextLogger("api").Debug("user not found in context")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	var (
		logger = bh.ContextLogger("api")
		err    error
		user   = r.Context().Value("user").(entity.User)
	)

	normalMode := bh.DBSvc.GetSetting("certificate_request_normal_mode")
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

	p, _ := pem.Decode(csrBytes)

	csr, err := x509.ParseCertificateRequest(p.Bytes)
	if err != nil {
		logger.Debugf("could not parse certificate signing request: %s", err.Error())
		http.Error(w, "malformed certificate signing request", http.StatusBadRequest)
		return
	}

	if dnsValidate := bh.DBSvc.GetSetting("certificate_request_require_domain_ownership"); dnsValidate == "true" {
		token, err := security.GenerateToken(global.ChallengeTokenLength)
		if err != nil {
			logger.Infof("error generating token: %s\n", err.Error())
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		val := r.Context().Value("user")
		u := val.(entity.User)

		ri := entity.RequestInfo{
			CreatedFor: u.ID,
			CsrBytes:   csrBytes,
			Token:      token,
			Status:     "accepted",
		}

		if err = bh.DBSvc.AddRequestInfo(&ri); err != nil {
			logger.Infof("error inserting request info: %s\n", err.Error())
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set(global.ChallengeLocationHeader, fmt.Sprintf(bh.Config.ServerHost+global.SolveChallengePath, ri.ID))
		w.WriteHeader(http.StatusAccepted)
		fmt.Fprint(w, token)

		return
	}

	sn, err := bh.CM.GenerateCertificateByCSR(csr)
	if err != nil {
		logger.Errorf("error generating certificate: %s\n", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	ci := entity.CertInfo{
		SerialNumber:   sn,
		FromCSR:        true,
		CreatedForUser: user.ID,
		Revoked:        false,
	}
	err = bh.DBSvc.AddCertInfo(&ci)
	if err != nil {
		logger.Errorf("could not insert cert info into DB: %s", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Add(global.CertificateLocationHeader, fmt.Sprintf(bh.Config.ServerHost+global.CertificateObtainPath, sn))
	w.WriteHeader(http.StatusCreated)
}

// ApiObtainCertificateHandler allows to actually download a certificate
func (bh *BaseHandler) ApiObtainCertificateHandler(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	var (
		logger = bh.ContextLogger("api")
		id     = mux.Vars(r)["id"]
	)

	certBytes, err := bh.CM.FindLeafCertificate(id)
	if err != nil {
		logger.Debugf("No certificate found for ID %s", id)
		w.WriteHeader(http.StatusNotFound)
		return
	}

	//w.Header().Set("Content-Disposition", "attachment; filename=\""+id+"-cert.pem\"")
	w.Header().Set("Content-Type", global.PemContentType)
	_, err = w.Write(certBytes)
	if err != nil {
		logger.Error("could not write cert bytes: " + err.Error())
	}
}

// ApiObtainPrivateKeyHandler allows to actually download a private key
func (bh *BaseHandler) ApiObtainPrivateKeyHandler(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	var (
		logger = bh.ContextLogger("api")
		vars   = mux.Vars(r)
		id     = vars["id"]
	)

	keyBytes, err := bh.CM.FindLeafPrivateKey(id)
	if err != nil {
		logger.Debugf("No private key found for ID %s", id)
		w.WriteHeader(http.StatusNotFound)
		return
	}

	//w.Header().Set("Content-Disposition", "attachment; filename=\""+id+"-key.pem\"")
	w.Header().Set("Content-Type", global.PemContentType)
	_, err = w.Write(keyBytes)
	if err != nil {
		logger.Error("could not write private key bytes: " + err.Error())
	}
}

// ApiOcspRequestHandler responds to OCSP requests with whether the certificate
// in question is revoked or not
func (bh *BaseHandler) ApiOcspRequestHandler(w http.ResponseWriter, r *http.Request) {
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

	rootCert, rootKey, err := bh.CM.GetRootKeyPair()
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

// ApiSolveChallengeHandler handles solving the challenges created for certificate request
func (bh *BaseHandler) ApiSolveChallengeHandler(w http.ResponseWriter, r *http.Request) {
	var (
		logger             = bh.ContextLogger("api")
		vars               = mux.Vars(r)
		b                  bytes.Buffer
		validationPort     string
		fromCsr            bool
		certificateRequest entity.SimpleRequest
		csr                x509.CertificateRequest
		attemptCount       = 0
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

	ri, err := bh.DBSvc.GetRequestInfo(vars["id"])
	if err != nil {
		logger.Debugf("could not get request info for ID %v", vars["id"])
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	contextUser := r.Context().Value("user")
	u := contextUser.(entity.User)

	if ri.CreatedFor != u.ID {
		logger.Errorf("user tried to to solve challenge from a different user")
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

	var domains []string
	if !fromCsr {
		domains = certificateRequest.Domains
	} else {
		domains = csr.DNSNames
	}

	ips := make([]string, 0)
	if !fromCsr {
		ips = certificateRequest.IPs
	} else {
		for _, v := range csr.IPAddresses {
			ips = append(ips, v.String())
		}

	}

	attemptCount = len(domains) + len(ips)

	// Domain validation
	for _, domain := range domains {
		attemptSuccessful := false
		// skip local dns names, like localhost or 127.0.0.1
		if helper.StringSliceContains(global.DnsNamesToSkip, domain) {
			attemptCount--
			continue
		}

		attempts := []string{
			fmt.Sprintf("https://%s:%s%s", domain, validationPort, global.WellKnownPath),
			fmt.Sprintf("http://%s:%s%s", domain, validationPort, global.WellKnownPath),
		}

		for _, attempt := range attempts {
			attemptSuccessful = false
			if attemptSuccessful { // no need to go on if already successful
				continue
			}

			req, err := http.NewRequest(http.MethodGet, attempt, nil)
			if err != nil {
				logger.Debugf("could not create request: %s", err.Error())
				attemptSuccessful = false
				continue
			}

			resp, err := bh.Client.Do(req)
			if err != nil {
				logger.Debugf("could not execute request for validation attempt: %s", err.Error())
				attemptSuccessful = false
				continue
			}
			_, err = io.Copy(&b, resp.Body)
			if err != nil {
				logger.Debugf("could not read request body from validation attempt: %s", err.Error())
				attemptSuccessful = false
				continue
			}
			_ = resp.Body.Close()

			if b.String() != ri.Token {
				logger.Debugf("invalid token")
				attemptSuccessful = false
				w.WriteHeader(http.StatusForbidden)
				return
			}

			attemptSuccessful = true
		}

		if attemptSuccessful {
			attemptCount--
		}
	}

	// IP validation
	for _, ip := range ips {
		attemptSuccessful := false
		// skip local dns names, like localhost or 127.0.0.1
		if helper.StringSliceContains(global.DnsNamesToSkip, ip) {
			attemptCount--
			continue
		}

		attempts := []string{
			fmt.Sprintf("https://%s:%s%s", ip, validationPort, global.WellKnownPath),
			fmt.Sprintf("http://%s:%s%s", ip, validationPort, global.WellKnownPath),
		}

		for _, attempt := range attempts {
			attemptSuccessful = false
			if attemptSuccessful { // no need to go on if already successful
				continue
			}

			req, err := http.NewRequest(http.MethodGet, attempt, nil)
			if err != nil {
				logger.Debugf("could not create request: %s", err.Error())
				attemptSuccessful = false
				continue
			}

			resp, err := bh.Client.Do(req)
			if err != nil {
				logger.Debugf("could not execute request for IP validation: %s", err.Error())
				attemptSuccessful = false
				continue
			}
			_, err = io.Copy(&b, resp.Body)
			if err != nil {
				logger.Debugf("could not read request body from HTTPS attempt: %s", err.Error())
				attemptSuccessful = false
				continue
			}
			_ = resp.Body.Close()

			if b.String() != ri.Token {
				logger.Debugf("invalid token")
				attemptSuccessful = false
				w.WriteHeader(http.StatusForbidden)
				return
			}

			attemptSuccessful = true
		}

		if attemptSuccessful {
			attemptCount--
		}
	}

	if attemptCount > 0 {
		logger.Debugf("%d validation attempt(s) was/were unsuccessful", attemptCount)
		w.WriteHeader(http.StatusExpectationFailed)
		return
	}

	logger.Debug("successfully validated")

	var sn int64
	if !fromCsr {
		sn, err = bh.CM.GenerateLeafCertAndKey(certificateRequest)
		if err != nil {
			logger.Errorf("error generating key + certificate: %s\n", err.Error())
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	} else {
		sn, err = bh.CM.GenerateCertificateByCSR(&csr)
		if err != nil {
			logger.Errorf("error generating key + certificate: %s\n", err.Error())
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	}

	ci := entity.CertInfo{
		SerialNumber:   sn,
		FromCSR:        fromCsr,
		CreatedForUser: u.ID,
		Revoked:        false,
	}

	if err = bh.DBSvc.AddCertInfo(&ci); err != nil {
		logger.Errorf("could not insert cert info into DB: %s", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	ri.Status = "finished"
	err = bh.DBSvc.UpdateRequestInfo(&ri)
	if err != nil {
		logger.Errorf("could not update request info: %s", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Add(global.CertificateLocationHeader, fmt.Sprintf(bh.Config.ServerHost+global.CertificateObtainPath, sn))
	if !fromCsr {
		w.Header().Add(global.PrivateKeyLocationHandler, fmt.Sprintf(bh.Config.ServerHost+global.PrivateKeyObtainPath, sn))
	}
}

// ApiRootCertificateDownloadHandler allows to programmatically obtain the root certificate
func (bh *BaseHandler) ApiRootCertificateDownloadHandler(w http.ResponseWriter, r *http.Request) {
	logger := bh.ContextLogger("api")

	certFile := filepath.Join(bh.Config.DataDir, global.RootCertificateFilename)
	fh, err := os.Open(certFile)
	if err != nil {
		logger.WithField("error", err.Error()).Error("could not open root cert file for reading")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", global.PemContentType)
	_, err = io.Copy(w, fh)
	if err != nil {
		logger.WithField("error", err.Error()).Error("could not write root cert contents")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	_ = fh.Close()
}

func (bh *BaseHandler) ApiRevokeCertificateHandler(w http.ResponseWriter, r *http.Request) {
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
