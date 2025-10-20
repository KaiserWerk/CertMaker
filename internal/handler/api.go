package handler

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
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
		user   = r.Context().Value("user").(*entity.User)
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

	var domainsToCheck []string
	for _, d := range certRequest.Domains {
		if helper.StringSliceContains(global.DNSNamesToSkip, d) {
			continue
		}
		domainsToCheck = append(domainsToCheck, d)
	}

	// set up response
	response := entity.CertificateResponse{}

	var hasChallenge bool
	if len(domainsToCheck) > 0 {
		if httpChallengeEnabled := bh.DBSvc.GetSetting(global.SettingEnableHTTP01Challenge); httpChallengeEnabled == "true" {
			hasChallenge = true
			ch := &entity.Challenge{
				CreatedFor:    user.ID,
				RequestInfoID: ri.ID,
				ChallengeID:   fmt.Sprintf("%d-%s", user.ID, security.GenerateToken(20)),
				ChallengeType: "http-01",
				ValidUntil:    time.Now().Add(global.DefaultChallengeValidity),
				Token:         security.GenerateToken(80),
			}
			if err = bh.DBSvc.AddChallenge(ch); err != nil {
				logger.Infof("error inserting challenge: %s\n", err.Error())
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			response.Challenges = append(response.Challenges, entity.ChallengeResponse{
				ChallengeType:  ch.ChallengeType,
				ChallengeID:    ch.ChallengeID,
				ChallengeToken: ch.Token,
				ValidUntil:     ch.ValidUntil.Format(time.RFC3339),
			})
		}
		// only allow DNS-01 challenge if no IPs are requested.
		// Those cannot be validated via DNS.
		if dnsChallengeEnabled := bh.DBSvc.GetSetting(global.SettingEnableDNS01Challenge); dnsChallengeEnabled == "true" && len(certRequest.IPs) == 0 {
			hasChallenge = true
			ch := &entity.Challenge{
				CreatedFor:    user.ID,
				RequestInfoID: ri.ID,
				ChallengeID:   fmt.Sprintf("%d-%s", user.ID, security.GenerateToken(20)),
				ChallengeType: "dns-01",
				ValidUntil:    time.Now().Add(global.DefaultChallengeValidity),
				Token:         security.GenerateToken(80),
			}
			if err = bh.DBSvc.AddChallenge(ch); err != nil {
				logger.Infof("error inserting challenge: %s\n", err.Error())
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			response.Challenges = append(response.Challenges, entity.ChallengeResponse{
				ChallengeType:  ch.ChallengeType,
				ChallengeID:    ch.ChallengeID,
				ChallengeToken: ch.Token,
				ValidUntil:     ch.ValidUntil.Format(time.RFC3339),
			})
		}
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

	certData, keyData, sn, err := bh.CertMaker.GenerateLeafCertAndKey(certRequest)
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

	response.CertificatePEM = certData
	response.PrivateKeyPEM = keyData

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
		user   = r.Context().Value("user").(*entity.User)
	)

	response := entity.CertificateResponse{}

	csrMode := bh.DBSvc.GetSetting(global.SettingEnableCSRRequestMode)
	if csrMode != "true" {
		w.WriteHeader(http.StatusNotImplemented)
		response.Error = "CSR mode is not enabled on this instance"
		_ = json.NewEncoder(w).Encode(response)
		return
	}

	csrBytes, err := io.ReadAll(r.Body)
	if err != nil {
		logger.Debugf("could not read request body: %s", err.Error())
		w.WriteHeader(http.StatusBadRequest)
		response.Error = "could not read request body"
		_ = json.NewEncoder(w).Encode(response)
		return
	}

	csr, err := x509.ParseCertificateRequest(csrBytes)
	if err != nil {
		logger.Debugf("could not parse certificate signing request: %s", err.Error())
		w.WriteHeader(http.StatusBadRequest)
		response.Error = "could not parse request body"
		_ = json.NewEncoder(w).Encode(response)
		return
	}

	u := r.Context().Value("user").(*entity.User)

	ri := entity.RequestInfo{
		CreatedFor: u.ID,
		CsrBytes:   csrBytes,
		Status:     global.RequestInfoStatusAccepted,
	}

	if err = bh.DBSvc.AddRequestInfo(&ri); err != nil {
		logger.Infof("error inserting request info: %s\n", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		response.Error = "internal server error"
		_ = json.NewEncoder(w).Encode(response)
		return
	}

	var domainsToCheck []string
	for _, d := range csr.DNSNames {
		if helper.StringSliceContains(global.DNSNamesToSkip, d) {
			continue
		}
		domainsToCheck = append(domainsToCheck, d)
	}

	var hasChallenge bool
	if len(domainsToCheck) > 0 {
		challengeID := fmt.Sprintf("%d-%s", user.ID, security.GenerateToken(20))
		expectedToken := security.GenerateToken(80)
		if httpChallengeEnabled := bh.DBSvc.GetSetting(global.SettingEnableHTTP01Challenge); httpChallengeEnabled == "true" {
			hasChallenge = true
			ch := &entity.Challenge{
				CreatedFor:    user.ID,
				RequestInfoID: ri.ID,
				ChallengeID:   challengeID,
				ChallengeType: "http-01",
				ValidUntil:    time.Now().Add(global.DefaultChallengeValidity),
				Token:         expectedToken,
			}
			if err = bh.DBSvc.AddChallenge(ch); err != nil {
				logger.Infof("error inserting challenge: %s\n", err.Error())
				w.WriteHeader(http.StatusInternalServerError)
				response.Error = "internal server error"
				_ = json.NewEncoder(w).Encode(response)
				return
			}
			response.Challenges = append(response.Challenges, entity.ChallengeResponse{
				ChallengeType:  ch.ChallengeType,
				ChallengeID:    ch.ChallengeID,
				ChallengeToken: ch.Token,
				ValidUntil:     ch.ValidUntil.Format(time.RFC3339),
			})
		}
		if dnsChallengeEnabled := bh.DBSvc.GetSetting(global.SettingEnableDNS01Challenge); dnsChallengeEnabled == "true" {
			hasChallenge = true
			ch := &entity.Challenge{
				CreatedFor:    user.ID,
				RequestInfoID: ri.ID,
				ChallengeID:   challengeID,
				ChallengeType: "dns-01",
				ValidUntil:    time.Now().Add(global.DefaultChallengeValidity),
				Token:         expectedToken,
			}
			if err = bh.DBSvc.AddChallenge(ch); err != nil {
				logger.Infof("error inserting challenge: %s\n", err.Error())
				w.WriteHeader(http.StatusInternalServerError)
				response.Error = "internal server error"
				_ = json.NewEncoder(w).Encode(response)
				return
			}
			response.Challenges = append(response.Challenges, entity.ChallengeResponse{
				ChallengeType:  ch.ChallengeType,
				ChallengeID:    ch.ChallengeID,
				ChallengeToken: ch.Token,
				ValidUntil:     ch.ValidUntil.Format(time.RFC3339),
			})
		}

	}

	if hasChallenge {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(response)
		return
	}

	// no challenge, issue certificate right away
	certBytes, sn, err := bh.CertMaker.GenerateCertificateByCSR(csr)
	if err != nil {
		logger.Errorf("error generating certificate: %s\n", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		response.Error = "internal server error"
		_ = json.NewEncoder(w).Encode(response)
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
		response.Error = "internal server error"
		_ = json.NewEncoder(w).Encode(response)
		return
	}

	response.CertificatePEM = string(certBytes)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)

	_ = json.NewEncoder(w).Encode(response)
}

// APIOCSPRequestHandler responds to OCSP requests with the revocation status of the certificate
// in question
func (bh *BaseHandler) APIOCSPRequestHandler(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	var (
		err    error
		logger = bh.ContextLogger("api")
		vars   = mux.Vars(r)
	)

	// handle content type headers
	w.Header().Set("Content-Type", "application/ocsp-response")
	if r.Header.Get("Content-Type") != "application/ocsp-request" {
		logger.Debug("incorrect content type header: " + r.Header.Get("Content-Type"))
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	var requestData []byte
	switch r.Method {
	case http.MethodPost:
		requestData, err = io.ReadAll(r.Body)
		if err != nil {
			logger.Debugf("could not read request body: %s", err.Error())
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		_ = r.Body.Close()
	case http.MethodGet:
		requestData, err = base64.StdEncoding.DecodeString(vars["base64"])
		if err != nil {
			logger.Debugf("could not base64 decode: %s", err.Error())
			w.WriteHeader(http.StatusBadRequest)
			return
		}
	}

	ocspReq, err := ocsp.ParseRequest(requestData)
	if err != nil {
		logger.Debug("could not parse OCSP Request: " + err.Error())
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	status := ocsp.Good
	ci, err := bh.DBSvc.FindCertInfo("serial_number = ?", ocspReq.SerialNumber.Int64())
	if err != nil {
		logger.Debug("could not find cert info: " + err.Error())
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if ci.Revoked {
		status = ocsp.Revoked
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
		NextUpdate:       time.Now().AddDate(0, 0, 1).UTC(),
		RevokedAt:        revokedAt,
		RevocationReason: ocsp.Unspecified,
		IssuerHash:       crypto.SHA512,
	}

	// maybe add nonce extension back in the future

	// nonce, err := ocsputil.ExtractNonceFromRequestDER(requestData)
	// if err != nil {
	// 	logger.Errorf("could not extract nonce from OCSP request: %s", err.Error())
	// 	w.WriteHeader(http.StatusBadRequest)
	// 	return
	// }

	// if nonce != nil {
	// 	nonceExt := pkix.Extension{
	// 		Id: ocsputil.OidOCSPNonce,
	// 		Value: ocsputil.MustASN1Marshal(asn1.RawValue{
	// 			Tag:   asn1.TagOctetString,
	// 			Class: asn1.ClassUniversal,
	// 			Bytes: nonce,
	// 		}),
	// 	}
	// 	responseTemplate.ExtraExtensions = []pkix.Extension{nonceExt}
	// }

	rootCert, rootKey, sigAlgo, err := bh.CertMaker.GetRootKeyPair()
	if err != nil {
		logger.Errorf("could not retrieve root certificate: %s", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	responseTemplate.SignatureAlgorithm = sigAlgo

	resp, err := ocsp.CreateResponse(rootCert, rootCert, responseTemplate, rootKey)
	if err != nil {
		logger.Errorf("could not create and sign OCSP response: %s", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	_, _ = w.Write(resp)
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
	challenge, err := bh.DBSvc.FindChallenge("challenge_id = ?", vars["challengeID"])
	if err != nil {
		if err == sql.ErrNoRows {
			logger.Debugf("no challenge found for challenge ID %s", vars["challengeID"])
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
			response.Error = fmt.Sprintf("failed HTTP-01 validation for domain %s: %s", domain, err.Error())
			w.WriteHeader(http.StatusBadRequest)
			err = json.NewEncoder(w).Encode(response)
			if err != nil {
				logger.Infof("could not encode response: %s", err.Error())
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			return
		}

		if !ok {
			response.Error = fmt.Sprintf("failed HTTP-01 validation for domain %s", domain)
			w.WriteHeader(http.StatusBadRequest)
			err = json.NewEncoder(w).Encode(response)
			if err != nil {
				logger.Infof("could not encode response: %s", err.Error())
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			return
		}
		logger.Debugf("HTTP-01 validation successful for domain %s", domain)
	}

	// check well known path for every IP
	for _, ip := range ips {
		if ip == "" {
			continue
		}

		if helper.StringSliceContains(global.IPsToSkip, ip) {
			continue
		}

		ok, err := challenges.CheckHTTP01Challenge(bh.Client, ip, request.ChallengePort, challenge.Token)
		if err != nil {
			response.Error = fmt.Sprintf("failed HTTP-01 validation for IP %s: %s", ip, err.Error())
			w.WriteHeader(http.StatusBadRequest)
			err = json.NewEncoder(w).Encode(response)
			if err != nil {
				logger.Infof("could not encode response: %s", err.Error())
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			return
		}

		if !ok {
			response.Error = fmt.Sprintf("failed HTTP-01 validation for IP %s", ip)
			w.WriteHeader(http.StatusBadRequest)
			err = json.NewEncoder(w).Encode(response)
			if err != nil {
				logger.Infof("could not encode response: %s", err.Error())
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			return
		}
		logger.Debugf("HTTP-01 validation successful for IP %s", ip)
	}

	// from here on, we know that the challenge was successful for all domains and IPs
	// that means we can issue the certificate
	var (
		certData, keyData string
		sn                int64
	)
	if fromCSR {
		// issue certificate from CSR
		certData, sn, err = bh.CertMaker.GenerateCertificateByCSR(csr)
		if err != nil {
			logger.Errorf("error generating certificate from CSR: %s\n", err.Error())
			w.WriteHeader(http.StatusInternalServerError)

			return
		}
	} else {
		certData, keyData, sn, err = bh.CertMaker.GenerateLeafCertAndKey(simpleRequest)
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
	response.CertificatePEM = certData
	if !fromCSR {
		response.PrivateKeyPEM = keyData
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
	challenge, err := bh.DBSvc.FindChallenge("challenge_id = ?", vars["challengeID"])
	if err != nil {
		if err == sql.ErrNoRows {
			logger.Debugf("no challenge found for challenge ID %s", vars["challengeID"])
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
		certData, keyData string
		sn                int64
	)
	if fromCSR {
		// issue certificate from CSR
		certData, sn, err = bh.CertMaker.GenerateCertificateByCSR(csr)
		if err != nil {
			logger.Errorf("error generating certificate from CSR: %s\n", err.Error())
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	} else {
		certData, keyData, sn, err = bh.CertMaker.GenerateLeafCertAndKey(simpleRequest)
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
	certInfo := &entity.CertInfo{
		SerialNumber:   sn,
		FromCSR:        fromCSR,
		CreatedForUser: challenge.CreatedFor,
		Revoked:        false,
	}

	err = bh.DBSvc.AddCertInfo(certInfo)
	if err != nil {
		logger.Errorf("could not insert cert info into DB: %s", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// set up response
	response.CertificatePEM = certData
	if !fromCSR {
		response.PrivateKeyPEM = keyData
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
		u      = r.Context().Value("user").(*entity.User)
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
