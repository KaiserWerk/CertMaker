package handler

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"strconv"
	"time"

	"github.com/KaiserWerk/CertMaker/internal/certmaker"
	"github.com/KaiserWerk/CertMaker/internal/entity"
	"github.com/KaiserWerk/CertMaker/internal/templating"
	"github.com/gorilla/mux"
)

func (bh *BaseHandler) AdminIssuerListHandler(w http.ResponseWriter, r *http.Request) {
	var (
		template = "admin_issuer_list.html"
		logger   = bh.ContextLogger("admin")
	)

	data := struct {
		Error   string
		Success string
		Info    string
		User    *entity.User
		Issuers []*entity.Issuer
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

	issuers, err := bh.DBSvc.GetAllIssuers()
	if err != nil {
		data.Error = "Could not retrieve issuers: " + err.Error()
		logger.Errorf("could not retrieve issuers: %s", err.Error())
		if err := templating.ExecuteTemplate(w, template, data); err != nil {
			logger.Errorf("could not execute template '%s': %s", template, err.Error())
		}
		return
	}
	data.Issuers = issuers

	if err := templating.ExecuteTemplate(w, template, data); err != nil {
		logger.Errorf("could not execute template '%s': %s", template, err.Error())
	}
}

func (bh *BaseHandler) AdminIssuerCreateHandler(w http.ResponseWriter, r *http.Request) {
	var (
		template = "admin_issuer_create.html"
		logger   = bh.ContextLogger("admin")
	)

	data := struct {
		Error   string
		Success string
		Info    string
		User    *entity.User
		Issuers []*entity.Issuer
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

	issuers, err := bh.DBSvc.GetAllIssuers()
	if err != nil {
		data.Error = "Could not retrieve issuers: " + err.Error()
		logger.Errorf("could not retrieve issuers: %s", err.Error())
		if err := templating.ExecuteTemplate(w, template, data); err != nil {
			logger.Errorf("could not execute template '%s': %s", template, err.Error())
		}
		return
	}
	data.Issuers = issuers

	if r.Method == http.MethodPost {
		issuerName := r.FormValue("issuer_name")
		if issuerName == "" {
			templating.SetErrorMessage(w, "Issuer name is required.")
			http.Redirect(w, r, "/admin/issuer/create", http.StatusSeeOther)
			return
		}

		var (
			parentIssuerID uint
			parentIssuer   *entity.Issuer
		)
		parentIssuerRaw := r.FormValue("parent_issuer")
		if parentIssuerRaw != "" {
			parentIssuerIDParsed, err := strconv.ParseUint(parentIssuerRaw, 10, 64)
			if err != nil {
				templating.SetErrorMessage(w, "Invalid parent issuer ID.")
				http.Redirect(w, r, "/admin/issuer/create", http.StatusSeeOther)
				return
			}

			parentIssuer, err = bh.DBSvc.FindIssuer("id = ?", parentIssuerIDParsed)
			if err != nil {
				templating.SetErrorMessage(w, "Parent issuer not found.")
				http.Redirect(w, r, "/admin/issuer/create", http.StatusSeeOther)
				return
			}

		} else {
			parentIssuerID = 0 // No parent issuer
		}

		// generate new private key
		keyAlgorithmRaw := r.FormValue("key_algorithm")

		keyLengthRaw := r.FormValue("key_length")
		keyLength, err := strconv.Atoi(keyLengthRaw)
		if err != nil {
			templating.SetErrorMessage(w, "Invalid value for key length.")
			http.Redirect(w, r, "/admin/issuer/create", http.StatusSeeOther)
			return
		}

		var (
			newPrivateKeyPEM  []byte
			signer            crypto.Signer
			signerPubKey      crypto.PublicKey
			issuerCertificate *x509.Certificate
		)
		switch keyAlgorithmRaw {
		case "rsa":
			// generate RSA private key
			privKey, err := rsa.GenerateKey(rand.Reader, keyLength)
			if err != nil {
				templating.SetErrorMessage(w, "Could not generate RSA private key: "+err.Error())
				http.Redirect(w, r, "/admin/issuer/create", http.StatusSeeOther)
				return
			}
			signer = privKey
			signerPubKey = privKey.Public()
			newPrivateKeyPEM, err = certmaker.EncodePrivateKeyToPEM(signer)
			if err != nil {
				templating.SetErrorMessage(w, "Could not encode RSA private key to PEM: "+err.Error())
				http.Redirect(w, r, "/admin/issuer/create", http.StatusSeeOther)
				return
			}
		case "ecdsa":
			// generate ECDSA private key
			var curve elliptic.Curve
			switch keyLength {
			case 256:
				curve = elliptic.P256()
			case 384:
				curve = elliptic.P384()
			case 521:
				curve = elliptic.P521()
			default:
				templating.SetErrorMessage(w, "Invalid key length for ECDSA. Allowed values are 256, 384, 521.")
				http.Redirect(w, r, "/admin/issuer/create", http.StatusSeeOther)
				return
			}

			privKey, err := ecdsa.GenerateKey(curve, rand.Reader)
			if err != nil {
				templating.SetErrorMessage(w, "Could not generate ECDSA private key: "+err.Error())
				http.Redirect(w, r, "/admin/issuer/create", http.StatusSeeOther)
				return
			}
			signer = privKey
			signerPubKey = privKey.Public()
			newPrivateKeyPEM, err = certmaker.EncodePrivateKeyToPEM(signer)
			if err != nil {
				templating.SetErrorMessage(w, "Could not encode ECDSA private key to PEM: "+err.Error())
				http.Redirect(w, r, "/admin/issuer/create", http.StatusSeeOther)
				return
			}
		case "ed25519":
			// generate Ed25519 private key
			publicKey, privKey, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				templating.SetErrorMessage(w, "Could not generate Ed25519 private key: "+err.Error())
				http.Redirect(w, r, "/admin/issuer/create", http.StatusSeeOther)
				return
			}
			signer = privKey
			signerPubKey = publicKey
			newPrivateKeyPEM, err = certmaker.EncodePrivateKeyToPEM(signer)
			if err != nil {
				templating.SetErrorMessage(w, "Could not encode Ed25519 private key to PEM: "+err.Error())
				http.Redirect(w, r, "/admin/issuer/create", http.StatusSeeOther)
				return
			}
		}

		if parentIssuerID != 0 { // intermediate issuer
			signer = parentIssuer.PrivateKey
		}

		subjectCommonNameRaw := r.FormValue("subject_common_name")
		subjectOrganizationRaw := r.FormValue("subject_organization")
		subjectOrganizationalUnitRaw := r.FormValue("subject_organizational_unit")
		subjectCountryRaw := r.FormValue("subject_country")
		subjectStateRaw := r.FormValue("subject_state")
		subjectLocalityRaw := r.FormValue("subject_locality")
		subjectPostalCodeRaw := r.FormValue("subject_postal_code")
		subjectStreetAddressRaw := r.FormValue("subject_street_address")
		// put everything into a pkix.Name structure
		subject := pkix.Name{
			CommonName:         subjectCommonNameRaw,
			Organization:       []string{subjectOrganizationRaw},
			OrganizationalUnit: []string{subjectOrganizationalUnitRaw},
			Country:            []string{subjectCountryRaw},
			Province:           []string{subjectStateRaw},
			Locality:           []string{subjectLocalityRaw},
			PostalCode:         []string{subjectPostalCodeRaw},
			StreetAddress:      []string{subjectStreetAddressRaw},
		}

		// generate a self-signed certificate or a certificate signed by the parent issuer
		newSerialNumber, err := certmaker.GetNextLeafSerialNumber(bh.Config.App.DataDir)
		if err != nil {
			templating.SetErrorMessage(w, "Could not get next serial number: "+err.Error())
			http.Redirect(w, r, "/admin/issuer/create", http.StatusSeeOther)
			return
		}

		yearsRaw := r.FormValue("validity_years")
		years, err := strconv.Atoi(yearsRaw)
		if err != nil {
			templating.SetErrorMessage(w, "Invalid value for validity years.")
			http.Redirect(w, r, "/admin/issuer/create", http.StatusSeeOther)
			return
		}

		certTemplate := &x509.Certificate{
			SerialNumber:          big.NewInt(newSerialNumber),
			Subject:               subject,
			NotBefore:             time.Now().UTC().Add(-24 * time.Hour),
			NotAfter:              time.Now().UTC().AddDate(years, 0, 0),
			KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
			BasicConstraintsValid: true,
			IsCA:                  true,
		}

		if parentIssuerID != 0 {
			issuerCertificate = parentIssuer.Certificate
		} else {
			issuerCertificate = certTemplate
		}
		newCert, err := x509.CreateCertificate(rand.Reader, certTemplate, issuerCertificate, signerPubKey, signer)
		if err != nil {
			templating.SetErrorMessage(w, "Could not create certificate: "+err.Error())
			http.Redirect(w, r, "/admin/issuer/create", http.StatusSeeOther)
			return
		}

		newIssuer := &entity.Issuer{
			ParentIssuerID: parentIssuerID,
			Name:           issuerName,
			Issuer:         certTemplate.Issuer.String(),
			Subject:        certTemplate.Subject.String(),
			SerialNumber:   uint64(newSerialNumber),
			NotBefore:      certTemplate.NotBefore,
			NotAfter:       certTemplate.NotAfter,
			CertificatePEM: newCert,
			PrivateKeyPEM:  newPrivateKeyPEM,
		}

		err = bh.DBSvc.AddIssuer(newIssuer)
		if err != nil {
			templating.SetErrorMessage(w, "Could not create issuer: "+err.Error())
			http.Redirect(w, r, "/admin/issuer/create", http.StatusSeeOther)
			return
		}

		templating.SetSuccessMessage(w, "Issuer created successfully!")
		http.Redirect(w, r, "/admin/issuer/list", http.StatusSeeOther)
		return
	}

	if err := templating.ExecuteTemplate(w, template, data); err != nil {
		logger.Errorf("could not execute template '%s': %s", template, err.Error())
	}
}

func (bh *BaseHandler) AdminIssuerDownloadRootCertificateHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	idRaw := vars["id"]
	id, err := strconv.ParseUint(idRaw, 10, 64)
	if err != nil {
		bh.Logger.Errorf("invalid issuer ID: %s", err.Error())
		http.Redirect(w, r, "/admin/issuer/list", http.StatusSeeOther)
		return
	}

	issuer, err := bh.DBSvc.FindIssuer("id = ?", id)
	if err != nil || issuer == nil {
		bh.Logger.Errorf("issuer not found: %s", err.Error())
		http.Redirect(w, r, "/admin/issuer/list", http.StatusSeeOther)
		return
	}

	filename := idRaw + "_root_certificate.pem"
	w.Header().Set("Content-Disposition", "attachment; filename="+filename)
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Write(issuer.CertificatePEM)
}
