package handler

import (
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"fmt"
	"github.com/KaiserWerk/CertMaker/internal/certmaker"
	"github.com/KaiserWerk/CertMaker/internal/dbservice"
	"github.com/KaiserWerk/CertMaker/internal/entity"
	"github.com/KaiserWerk/CertMaker/internal/global"
	"github.com/KaiserWerk/CertMaker/internal/helper"
	"github.com/KaiserWerk/CertMaker/internal/logging"
	"github.com/KaiserWerk/CertMaker/internal/templates"
	"github.com/gorilla/mux"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// CertificateListHandler lists all available certificates and
// private keys in the UI
func CertificateListHandler(w http.ResponseWriter, r *http.Request) {
	var (
		logger = logging.GetLogger().WithField("function", "handler.CertificateListHandler")
		ds     = dbservice.New()
	)
	// read certificates from db
	ci, err := ds.GetAllCertInfo()
	if err != nil {
		logger.Errorf("could not fetch cert info entries")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	var targetCertInfos []entity.CertInfo

	val := r.Context().Value("user")
	u := val.(entity.User)
	if u.Admin == false {
		for _, v := range ci {
			if v.CreatedForUser == u.ID {
				targetCertInfos = append(targetCertInfos, v)
			}
		}
	} else {
		targetCertInfos = ci
	}

	data := struct {
		CertInfos []entity.CertInfo
	}{
		CertInfos: targetCertInfos,
	}

	if err := templates.ExecuteTemplate(w, "certificate/certificate_list.gohtml", data); err != nil {
		w.WriteHeader(http.StatusNotFound)
	}
}

func RootCertificateDownloadHandler(w http.ResponseWriter, r *http.Request) {
	var (
		logger = logging.GetLogger().WithField("function", "handler.RootCertificateDownloadHandler")
		config = global.GetConfiguration()
	)

	certFile := filepath.Join(config.DataDir, global.RootCertificateFilename)
	fh, err := os.Open(certFile)
	if err != nil {
		logger.Errorf("could not open root cert file for reading: %s", err.Error())
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

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
func CertificateDownloadHandler(w http.ResponseWriter, r *http.Request) {
	var (
		logger = logging.GetLogger().WithField("function", "handler.CertificateDownloadHandler")
		config = global.GetConfiguration()
		ds     = dbservice.New()
		vars   = mux.Vars(r)
		u      = r.Context().Value("user").(entity.User)
	)

	ci, err := ds.FindCertInfo("id = ?", vars["id"])
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

	filename := fmt.Sprintf("%d-cert.pem", ci.SerialNumber)
	certContent, err := ioutil.ReadFile(filepath.Join(config.DataDir, "leafcerts", filename))
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
func PrivateKeyDownloadHandler(w http.ResponseWriter, r *http.Request) {
	var (
		logger = logging.GetLogger().WithField("function", "handler.PrivateKeyDownloadHandler")
		config = global.GetConfiguration()
		ds     = dbservice.New()
		vars   = mux.Vars(r)
		u      = r.Context().Value("user").(entity.User)
	)

	ci, err := ds.FindCertInfo("id = ?", vars["id"])
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

	filename := fmt.Sprintf("%d-key.pem", ci.SerialNumber)
	certContent, err := ioutil.ReadFile(filepath.Join(config.DataDir, "leafcerts", filename))
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
func CertificateAddHandler(w http.ResponseWriter, r *http.Request) {
	var (
		logger = logging.GetLogger().WithField("function", "handler.CertificateAddHandler")
		ds     = dbservice.New()
	)

	if simpleMode := ds.GetSetting("certificate_request_simple_mode"); simpleMode != "true" {
		logger.Debug("simple mode is not enabled")
		http.Redirect(w, r, "/certificate/list", http.StatusSeeOther)
		return
	}

	if r.Method == http.MethodPost {
		organization := r.FormValue("organization")
		country := r.FormValue("country")
		province := r.FormValue("province")
		locality := r.FormValue("locality")
		streetAddress := r.FormValue("street_address")
		postalCode := r.FormValue("postal_code")
		days := r.FormValue("days")
		if organization == "" || country == "" || province == "" || locality == "" || streetAddress == "" ||
			postalCode == "" || days == "" {
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
			Subject: struct {
				Organization  string `json:"organization"`
				Country       string `json:"country"`
				Province      string `json:"province"`
				Locality      string `json:"locality"`
				StreetAddress string `json:"street_address"`
				PostalCode    string `json:"postal_code"`
			}{
				Organization:  organization,
				Country:       country,
				Province:      province,
				Locality:      locality,
				StreetAddress: streetAddress,
				PostalCode:    postalCode,
			},
			Days: daysVal,
		}

		sn, err := certmaker.GenerateLeafCertAndKey(certRequest)
		if err != nil {
			logger.Error("could not generate leaf cert and key: " + err.Error())
			http.Redirect(w, r, "/add", http.StatusSeeOther)
			return
		}

		userFromContext := r.Context().Value("user")
		u := userFromContext.(entity.User)

		ci := entity.CertInfo{
			SerialNumber:   sn,
			FromCSR:        false,
			CreatedForUser: u.ID,
			Revoked:        false,
		}
		err = ds.AddCertInfo(&ci)
		if err != nil {
			logger.Errorf("could not insert cert info into DB: %s", err.Error())
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	data := struct {
		DefaultDays int
	}{
		DefaultDays: global.CertificateDefaultDays,
	}

	if err := templates.ExecuteTemplate(w, "certificate/certificate_add.gohtml", data); err != nil {
		w.WriteHeader(http.StatusNotFound)
	}
}

// AddCertificateFromCSRHandler enables you to upload a file containing a CSR to
// the UI and create a certificate
func AddCertificateFromCSRHandler(w http.ResponseWriter, r *http.Request) {
	var (
		logger = logging.GetLogger().WithField("function", "handler.AddCertificateFromCSRHandler")
		ds     = dbservice.New()
	)

	if r.Method == http.MethodPost {

		csrFile, _, err := r.FormFile("csr_file")
		if err != nil {
			logger.Debug("could not perform CSR upload: " + err.Error())
			http.Redirect(w, r, "/certificate/list", http.StatusSeeOther)
			return
		}

		csrBytes, err := ioutil.ReadAll(csrFile)
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

		sn, err := certmaker.GenerateCertificateByCSR(csr)
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
		err = ds.AddCertInfo(&ci)
		if err != nil {
			logger.Errorf("could not insert cert info into DB: %s", err.Error())
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	}

	if err := templates.ExecuteTemplate(w, "certificate/certificate_add_with_csr.gohtml", nil); err != nil {
		w.WriteHeader(http.StatusNotFound)
	}
}

// RevokeCertificateHandler allows the revocation of a certificate via the UI
func RevokeCertificateHandler(w http.ResponseWriter, r *http.Request) {
	var (
		logger = logging.GetLogger().WithField("function", "handler.RevokeCertificateHandler")
		ds     = dbservice.New()
		vars   = mux.Vars(r)
		u      = r.Context().Value("user").(entity.User)
	)

	ci, err := ds.FindCertInfo("id = ?", vars["id"])
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

	err = ds.UpdateCertInfo(&ci)
	if err != nil {
		logger.Errorf("could not update CertInfo entry")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/certificate/list", http.StatusSeeOther)
}
