package handler

import (
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/KaiserWerk/CertMaker/internal/entity"
	"github.com/KaiserWerk/CertMaker/internal/global"
	"github.com/KaiserWerk/CertMaker/internal/helper"
	"github.com/KaiserWerk/CertMaker/internal/templating"

	"github.com/gorilla/mux"
)

// CertificateListHandler lists all available certificates and
// private keys in the UI
func (bh *BaseHandler) CertificateListHandler(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	const template = "certificate_list.html"
	logger := bh.ContextLogger("certificate")

	data := struct {
		Error     string
		Success   string
		Info      string
		User      *entity.User
		CertInfos []entity.CertInfo
	}{
		Error:   templating.GetErrorMessage(w, r),
		Success: templating.GetSuccessMessage(w, r),
		Info:    templating.GetInfoMessage(w, r),
	}

	user, ok := r.Context().Value("user").(*entity.User)
	if !ok || user == nil {
		http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
		return
	}
	data.User = user

	// read certificates from db
	ci, err := bh.DBSvc.GetAllCertInfo()
	if err != nil {
		logger.Errorf("could not fetch cert info entries")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	var targetCertInfos []entity.CertInfo

	if !user.Admin {
		for _, v := range ci {
			if v.CreatedForUser == user.ID {
				targetCertInfos = append(targetCertInfos, v)
			}
		}
	} else {
		targetCertInfos = ci
	}
	data.CertInfos = targetCertInfos

	if err := templating.ExecuteTemplate(w, template, data); err != nil {
		logger.Errorf("could not execute template: %s", err.Error())
	}
}

func (bh *BaseHandler) RootCertificateDownloadHandler(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	logger := bh.ContextLogger("certificate")

	certFile := filepath.Join(bh.Config.DataDir, global.RootCertificateFilename)
	fh, err := os.Open(certFile)
	if err != nil {
		logger.Errorf("could not open root cert file for reading: %s", err.Error())
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	w.Header().Set("Content-Type", global.PemContentType)
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, global.RootCertificateFilename))

	_, err = io.Copy(w, fh)
	if err != nil {
		logger.Errorf("could not write root cert contents: %s", err.Error())
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	_ = fh.Close()
}

// CertificateDownloadHandler downloads a certificate requested via UI
func (bh *BaseHandler) CertificateDownloadHandler(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	var user entity.User
	if r.Context().Value("user") != nil {
		user = r.Context().Value("user").(entity.User)
	}
	var (
		logger = bh.ContextLogger("certificate")
		vars   = mux.Vars(r)
	)

	ci, err := bh.DBSvc.FindCertInfo("id = ?", vars["id"])
	if err != nil {
		logger.Debug("could not find cert info: " + err.Error())
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if ci.CreatedForUser != user.ID && !user.Admin {
		logger.Error("This is not your private key")
		w.WriteHeader(http.StatusForbidden)
		return
	}

	filename := fmt.Sprintf("%d-cert.pem", ci.SerialNumber)
	certContent, err := os.ReadFile(filepath.Join(bh.Config.DataDir, "leafcerts", filename))
	if err != nil {
		logger.Debug("could not read certificate file: " + err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", global.PemContentType)
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
	w.Write(certContent)
}

// PrivateKeyDownloadHandler downloads a private key requested via UI
func (bh *BaseHandler) PrivateKeyDownloadHandler(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	var user entity.User
	if r.Context().Value("user") != nil {
		user = r.Context().Value("user").(entity.User)
	}
	var (
		logger = bh.ContextLogger("certificate")
		vars   = mux.Vars(r)
	)

	ci, err := bh.DBSvc.FindCertInfo("id = ?", vars["id"])
	if err != nil {
		logger.Debug("could not find cert info: " + err.Error())
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if ci.CreatedForUser != user.ID && !user.Admin {
		logger.Error("This is not your private key")
		w.WriteHeader(http.StatusForbidden)
		return
	}

	filename := fmt.Sprintf("%d-key.pem", ci.SerialNumber)
	certContent, err := os.ReadFile(filepath.Join(bh.Config.DataDir, "leafcerts", filename))
	if err != nil {
		logger.Debug("could not read key file: " + err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", global.PemContentType)
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
	w.Write(certContent)
}

// CertificateAddHandler allows to add a new certificate + private key via UI
func (bh *BaseHandler) CertificateAddHandler(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	const template = "certificate_add.html"
	logger := bh.ContextLogger("certificate")

	if simpleMode := bh.DBSvc.GetSetting(global.SettingEnableSimpleRequestMode); simpleMode != "true" {
		templating.SetErrorMessage(w, "Simple Request Mode is not enabled.")
		http.Redirect(w, r, "/certificate/list", http.StatusSeeOther)
		return
	}

	data := struct {
		Error       string
		Success     string
		Info        string
		User        *entity.User
		DefaultDays int
	}{
		Error:       templating.GetErrorMessage(w, r),
		Success:     templating.GetSuccessMessage(w, r),
		Info:        templating.GetInfoMessage(w, r),
		DefaultDays: global.CertificateDefaultDays,
	}

	user, ok := r.Context().Value("user").(*entity.User)
	if !ok || user == nil {
		http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
		return
	}
	data.User = user

	if r.Method == http.MethodPost {
		organization := r.FormValue("organization")
		country := r.FormValue("country")
		province := r.FormValue("province")
		locality := r.FormValue("locality")
		streetAddress := r.FormValue("street_address")
		postalCode := r.FormValue("postal_code")
		commonName := r.FormValue("common_name")
		days := r.FormValue("days")
		if days == "" {
			logger.Debug("please fill in all required fields, marked with *")
			http.Redirect(w, r, "/certificate/add", http.StatusSeeOther)
			return
		}

		daysVal, err := strconv.Atoi(days)
		if err != nil {
			logger.Debug("no valid numeric value for field 'days' supplied!")
			http.Redirect(w, r, "/certificate/add", http.StatusSeeOther)
			return
		}

		domainList := make([]string, 0)
		domains := r.FormValue("domains")
		if strings.Contains(domains, ",") {
			parts := strings.Split(domains, ",")
			helper.TrimSliceElements(parts)
			domainList = append(domainList, parts...)
		} else {
			domainList = append(domainList, strings.TrimSpace(domains))
		}
		ipList := make([]string, 0)
		ips := r.FormValue("ips")
		if strings.Contains(ips, ",") {
			parts := strings.Split(ips, ",")
			helper.TrimSliceElements(parts)
			ipList = append(ipList, parts...)
		} else {
			ipList = append(ipList, strings.TrimSpace(ips))
		}

		certRequest := entity.SimpleRequest{
			Domains: domainList,
			IPs:     ipList,
			Subject: entity.Subject{
				CommonName:    commonName,
				Organization:  organization,
				Country:       country,
				Province:      province,
				Locality:      locality,
				StreetAddress: streetAddress,
				PostalCode:    postalCode,
			},
			Days: daysVal,
		}

		sn, err := bh.CertMaker.GenerateLeafCertAndKey(certRequest)
		if err != nil {
			logger.Error("could not generate leaf cert and key: " + err.Error())
			http.Redirect(w, r, "/certificate/add", http.StatusSeeOther)
			return
		}

		user := r.Context().Value("user").(entity.User)

		ci := entity.CertInfo{
			SerialNumber:   sn,
			FromCSR:        false,
			CreatedForUser: user.ID,
			Revoked:        false,
		}
		err = bh.DBSvc.AddCertInfo(&ci)
		if err != nil {
			logger.Errorf("could not insert certificate info into DB: %s", err.Error())
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}

		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	if err := templating.ExecuteTemplate(w, template, data); err != nil {
		logger.Errorf("could not execute template: %s", err.Error())
	}
}

// AddCertificateFromCSRHandler enables you to upload a file containing a CSR to
// the UI and create a certificate
func (bh *BaseHandler) AddCertificateFromCSRHandler(w http.ResponseWriter, r *http.Request) {
	logger := bh.ContextLogger("certificate")
	const template = "certificate_add_with_csr.html"

	if csrMode := bh.DBSvc.GetSetting(global.SettingEnableCSRRequestMode); csrMode != "true" {
		templating.SetErrorMessage(w, "CSR Request Mode is not enabled.")
		http.Redirect(w, r, "/certificate/list", http.StatusSeeOther)
		return
	}

	data := struct {
		Error   string
		Success string
		Info    string
		User    *entity.User
	}{
		Error:   templating.GetErrorMessage(w, r),
		Success: templating.GetSuccessMessage(w, r),
		Info:    templating.GetInfoMessage(w, r),
	}

	user, ok := r.Context().Value("user").(*entity.User)
	if !ok || user == nil {
		http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
		return
	}
	data.User = user

	if r.Method == http.MethodPost {

		csrFile, _, err := r.FormFile("csr_file")
		if err != nil {
			logger.Debug("could not perform CSR upload: " + err.Error())
			http.Redirect(w, r, "/certificate/list", http.StatusSeeOther)
			return
		}

		csrBytes, err := io.ReadAll(csrFile)
		if err != nil {
			logger.Debug("could not read uploaded CSR file: " + err.Error())
			http.Redirect(w, r, "/certificate/list", http.StatusSeeOther)
			return
		}

		p, _ := pem.Decode(csrBytes)

		csr, err := x509.ParseCertificateRequest(p.Bytes)
		if err != nil {
			logger.Debug("could not parse uploaded CSR file: " + err.Error())
			http.Redirect(w, r, "/certificate/list", http.StatusSeeOther)
			return
		}
		err = csr.CheckSignature()
		if err != nil {
			logger.Debug("CSR signature could not be verified: " + err.Error())
			http.Redirect(w, r, "/certificate/list", http.StatusSeeOther)
			return
		}

		sn, err := bh.CertMaker.GenerateCertificateByCSR(csr)
		if err != nil {
			logger.Debug("could not generate certificate FROM CSR: " + err.Error())
			http.Redirect(w, r, "/certificate/list", http.StatusSeeOther)
			return
		}

		userFromContext := r.Context().Value("user")
		u := userFromContext.(entity.User)

		ci := entity.CertInfo{
			SerialNumber:   sn,
			FromCSR:        true,
			CreatedForUser: u.ID,
		}
		err = bh.DBSvc.AddCertInfo(&ci)
		if err != nil {
			logger.Errorf("could not insert cert info into DB: %s", err.Error())
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	}

	if err := templating.ExecuteTemplate(w, template, data); err != nil {
		logger.Errorf("could not execute template '%s': %s", template, err.Error())
	}
}

// RevokeCertificateHandler allows the revocation of a certificate via the UI
func (bh *BaseHandler) RevokeCertificateHandler(w http.ResponseWriter, r *http.Request) {
	var (
		logger = bh.ContextLogger("certificate")
		vars   = mux.Vars(r)
		u      = r.Context().Value("user").(entity.User)
	)

	ci, err := bh.DBSvc.FindCertInfo("id = ?", vars["id"])
	if err != nil {
		logger.Debug("could not find cert info: " + err.Error())
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if ci.CreatedForUser != u.ID && !u.Admin {
		logger.Error("This is not your private key")
		w.WriteHeader(http.StatusForbidden)
		return
	}

	ci.Revoked = true
	ci.RevokedAt = sql.NullTime{Time: time.Now(), Valid: true}

	err = bh.DBSvc.UpdateCertInfo(&ci)
	if err != nil {
		logger.Errorf("could not update CertInfo entry")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/certificate/list", http.StatusSeeOther)
}
