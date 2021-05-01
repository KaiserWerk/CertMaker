package main

import (
	"encoding/json"
	"fmt"
	"github.com/gorilla/mux"
	"golang.org/x/crypto/ocsp"
	"io/ioutil"
	"log"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
)

func indexHandler(w http.ResponseWriter, r *http.Request) {
	// auth

	var files []string

	err := filepath.Walk(globalConfig.DataDir + "/leafcerts", visit(&files))
	if err != nil {
		fmt.Println("could not read files: " + err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	var certs []string
	for _, file := range files {
		p := strings.Split(file, "\\")
		//fmt.Println("file:", p[len(p) - 1])
		parts := strings.Split(p[len(p) - 1], "-")
		certs = append(certs, parts[0])
	}

	data := struct {
		CertSNs []string
	}{
		CertSNs: certs,
	}

	if err := executeTemplate(w, "index.gohtml", data); err != nil {
		w.WriteHeader(404)
	}
}
func addCertificateHandler(w http.ResponseWriter, r *http.Request) {
	// auth

	if r.Method == http.MethodPost {
		organization := r.FormValue("organization")
		country := r.FormValue("country")
		province := r.FormValue("province")
		locality := r.FormValue("locality")
		streetAddress := r.FormValue("street_address")
		postalCode := r.FormValue("postal_code")
		days := r.FormValue("days")
		fmt.Println(organization, country, province, locality, streetAddress, postalCode, days)
		if organization == "" || country == "" || province == "" || locality == "" || streetAddress == "" ||
			postalCode == "" || days == "" {
			fmt.Println("please fill in all required fields, marked with *")
			http.Redirect(w, r, "/add", http.StatusSeeOther)
			return
		}

		daysVal, err := strconv.Atoi(days)
		if err != nil {
			fmt.Println("no valid value for field 'days' supplied!")
			http.Redirect(w, r, "/add", http.StatusSeeOther)
			return
		}

		domainList := make([]string, 0)
		domains := r.FormValue("domains")
		if strings.Contains(domains, ",") {
			parts := strings.Split(domains, ",")
			trimSliceElements(parts)
			domainList = append(domainList, parts...)
		} else {
			domainList = append(domainList, strings.TrimSpace(domains))
		}
		ipList := make([]string, 0)
		ips := r.FormValue("ips")
		if strings.Contains(ips, ",") {
			parts := strings.Split(ips, ",")
			trimSliceElements(parts)
			ipList = append(ipList, parts...)
		} else {
			ipList = append(ipList, strings.TrimSpace(ips))
		}

		certReq := certificateRequest{
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

		_, err = generateLeafCertAndKey(certReq)
		if err != nil {
			fmt.Println("could not generate leaf cert and key: " + err.Error())
			http.Redirect(w, r, "/add", http.StatusSeeOther)
			return
		}

		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	if err := executeTemplate(w, "add_certificate.gohtml", nil); err != nil {
		w.WriteHeader(404)
	}
}

func removeCertificateHandler(w http.ResponseWriter, r *http.Request) {
	// auth

}

func certificateRequestHandler(w http.ResponseWriter, r *http.Request) {
	// dont forget authentication

	var certRequest certificateRequest
	err := json.NewDecoder(r.Body).Decode(&certRequest)
	if err != nil {
		log.Printf("error parsing certificate request: %s\n", err.Error())
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	_ = r.Body.Close()

	sn, err := generateLeafCertAndKey(certRequest)
	if err != nil {
		log.Printf("error generating key + certificate: %s\n", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Add("X-Certificate-Location", fmt.Sprintf("http://%s/api/certificate/%d/obtain", globalConfig.ServerHost, sn))
	w.Header().Add("X-Privatekey-Location", fmt.Sprintf("http://%s/api/privatekey/%d/obtain", globalConfig.ServerHost, sn))
}

func certificateObtainHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	certBytes, err := findLeafCertificate(id)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	_, err = w.Write(certBytes)
	if err != nil {
		log.Println("could not write cert bytes:", err.Error())
	}
}

func privateKeyObtainHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	keyBytes, err := findLeafPrivateKey(id)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	_, err = w.Write(keyBytes)
	if err != nil {
		log.Println("could not write privkey bytes:", err.Error())
	}
}

func oscpRequestHandler(w http.ResponseWriter, r *http.Request) {
	/*
	httpReq.Header.Add("Content-Type", "application/ocsp-request")
				httpReq.Header.Add("Accept", "application/ocsp-response")
				httpReq.Header.Add("Host", ocspUrl.Host)
	 */
	if r.Header.Get("Content-Type") != "application/ocsp-request" {
		log.Println("incorrect content type header: " + r.Header.Get("Content-Type"))
		w.Write([]byte("Wrong Content-Type header: must be application/ocsp-request"))
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if r.Header.Get("Accept") != "application/ocsp-response" {
		log.Println("incorrect Accept header: " + r.Header.Get("Accept"))
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
		log.Println("could not read request body: " + err.Error())
		w.Write([]byte("could not read request body: " + err.Error()))
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	_ = r.Body.Close()
	ocspReq, err := ocsp.ParseRequest(reqBody)
	if err != nil {
		log.Println("could not parse OCSP Request: " + err.Error())
		w.Write([]byte("could not parse OCSP Request: " + err.Error()))
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	fmt.Println(ocspReq.SerialNumber)

	// hier prüfen, ob das Cert wirklich revoked ist
	// ...

	//ocspResp := ocsp.CreateResponse()
}