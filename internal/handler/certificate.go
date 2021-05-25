package handler

import (
	"github.com/KaiserWerk/CertMaker/internal/certmaker"
	"github.com/KaiserWerk/CertMaker/internal/entity"
	"github.com/KaiserWerk/CertMaker/internal/global"
	"github.com/KaiserWerk/CertMaker/internal/helper"
	"github.com/KaiserWerk/CertMaker/internal/logging"
	"github.com/KaiserWerk/CertMaker/internal/templateservice"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
)

// ListCertificateHandler lists all available certificates and
// private keys in the UI
func ListCertificateHandler(w http.ResponseWriter, r *http.Request) {
	config := global.GetConfiguration()
	logger := logging.GetLogger()
	var files []string

	err := filepath.Walk(config.DataDir + "/leafcerts", helper.Visit(&files))
	if err != nil {
		logger.Println("could not read files: " + err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	var certs []string
	for _, file := range files {
		p := strings.Split(file, "\\")
		parts := strings.Split(p[len(p) - 1], "-")
		certs = append(certs, parts[0])
	}

	data := struct {
		CertSNs []string
	}{
		CertSNs: certs,
	}

	if err := templateservice.ExecuteTemplate(w, "certificate/certificate_list.gohtml", data); err != nil {
		w.WriteHeader(http.StatusNotFound)
	}
}

// AddCertificateHandler allows to add a new certificate + private key via UI
func AddCertificateHandler(w http.ResponseWriter, r *http.Request) {

	// TODO enforce simple mode

	logger := logging.GetLogger()
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
			logger.Println("please fill in all required fields, marked with *")
			http.Redirect(w, r, "/add", http.StatusSeeOther)
			return
		}

		daysVal, err := strconv.Atoi(days)
		if err != nil {
			logger.Println("no valid value for field 'days' supplied!")
			http.Redirect(w, r, "/add", http.StatusSeeOther)
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

		certReq := entity.CertificateRequest{
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

		_, err = certmaker.GenerateLeafCertAndKey(certReq)
		if err != nil {
			logger.Println("could not generate leaf cert and key: " + err.Error())
			http.Redirect(w, r, "/add", http.StatusSeeOther)
			return
		}

		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	if err := templateservice.ExecuteTemplate(w, "certificate/certificate_add.gohtml", nil); err != nil {
		w.WriteHeader(http.StatusNotFound)
	}
}

// AddCertificateWithCSRHandler enables you to upload a file containing a CSR to
// the UI and create a certificate
func AddCertificateWithCSRHandler(w http.ResponseWriter, r *http.Request) {
	if err := templateservice.ExecuteTemplate(w, "certificate/certificate_add_with_csr.gohtml", nil); err != nil {
		w.WriteHeader(http.StatusNotFound)
	}
}

// RevokeCertificateHandler allows the revocation of a certificate via the UI
func RevokeCertificateHandler(w http.ResponseWriter, r *http.Request) {

}
