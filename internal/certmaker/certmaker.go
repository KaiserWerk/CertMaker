package certmaker

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"time"

	"github.com/KaiserWerk/CertMaker/internal/configuration"
	"github.com/KaiserWerk/CertMaker/internal/dbservice"
	"github.com/KaiserWerk/CertMaker/internal/entity"
	"github.com/KaiserWerk/CertMaker/internal/global"
)

type (
	Algo string
)

const (
	RSA     Algo = "rsa"
	ECDSA   Algo = "ecdsa"
	ED25519 Algo = "ed25519"
)

type CertMaker struct {
	config                *configuration.AppConfig
	serialNumberGenerator SerialNumberGenerator
}

func NewCertMaker(config *configuration.AppConfig, dbService *dbservice.DBService) *CertMaker {
	return &CertMaker{
		config:                config,
		serialNumberGenerator: NewDBSerialNumberGenerator(dbService),
	}
}

func (cm *CertMaker) NextSerialNumber() (int64, error) {
	return cm.serialNumberGenerator.Next()
}

// CertificateAndPrivateKeyFromSimpleRequest generates a private key as well as a certificate signed by the supplied issuer.
func (cm *CertMaker) CertificateAndPrivateKeyFromSimpleRequest(issuer *entity.Issuer, request entity.SimpleRequest) ([]byte, []byte, int64, error) {
	if request.Validity > global.CertificateMaxValidity {
		request.Validity = global.CertificateMaxValidity
	}

	if request.Validity < global.CertificateMinValidity {
		request.Validity = global.CertificateMinValidity
	}

	ips := make([]net.IP, 0)
	for _, v := range request.IPs {
		ip := net.ParseIP(v)
		if ip != nil {
			ips = append(ips, ip)
		}
	}

	nextSn, err := cm.serialNumberGenerator.Next()
	if err != nil {
		return nil, nil, 0, err
	}

	ski, err := subjectKeyIDFromSimpleRequest(request)
	if err != nil {
		return nil, nil, 0, err
	}

	cert := &x509.Certificate{
		SerialNumber: big.NewInt(nextSn),
		Subject: pkix.Name{
			CommonName:    request.Subject.CommonName,
			Country:       []string{request.Subject.Country},
			Organization:  []string{request.Subject.Organization},
			Locality:      []string{request.Subject.Locality},
			Province:      []string{request.Subject.Province},
			StreetAddress: []string{request.Subject.StreetAddress},
			PostalCode:    []string{request.Subject.PostalCode},
		},
		NotBefore:          time.Now(),
		NotAfter:           time.Now().Add(request.Validity),
		SignatureAlgorithm: issuer.Certificate.SignatureAlgorithm,
		SubjectKeyId:       ski,
		ExtKeyUsage:        []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:           x509.KeyUsageDigitalSignature,
		OCSPServer:         []string{cm.config.App.ServerHost + global.OCSPPath},

		DNSNames:       request.Domains,
		IPAddresses:    ips,
		EmailAddresses: request.EmailAddresses,
	}

	var (
		privKey any
		pubKey  crypto.PublicKey
	)

	switch issuer.Certificate.SignatureAlgorithm {
	case x509.SHA256WithRSA, x509.SHA384WithRSA, x509.SHA512WithRSA:
		rsaPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
		if err != nil {
			return nil, nil, 0, err
		}
		privKey = rsaPrivKey
		pubKey = &rsaPrivKey.PublicKey
	case x509.ECDSAWithSHA256, x509.ECDSAWithSHA384, x509.ECDSAWithSHA512:
		ecdsaPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, nil, 0, err
		}
		privKey = ecdsaPrivKey
		pubKey = &ecdsaPrivKey.PublicKey

	case x509.PureEd25519:
		edPubKey, edPrivKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, 0, err
		}
		privKey = edPrivKey
		pubKey = edPubKey
	}

	// Sign the certificate
	certBytes, err := x509.CreateCertificate(rand.Reader, cert, issuer.Certificate, pubKey, issuer.PrivateKey)
	if err != nil {
		return nil, nil, 0, err
	}

	// cert with public key
	certOut := &bytes.Buffer{}
	err = pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	if err != nil {
		return nil, nil, 0, err
	}

	// private key
	privKeyOut := &bytes.Buffer{}
	privKeyBytes, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return nil, nil, 0, err
	}
	err = pem.Encode(privKeyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: privKeyBytes})
	if err != nil {
		return nil, nil, 0, err
	}

	return certOut.Bytes(), privKeyOut.Bytes(), nextSn, nil
}

// CertificateFromCSR generates a certificate from the provided CSR using the supplied signer.
func (cm *CertMaker) CertificateFromCSR(issuer *entity.Issuer, csr *x509.CertificateRequest, validity time.Duration) ([]byte, int64, error) {
	sn, err := cm.serialNumberGenerator.Next()
	if err != nil {
		return nil, 0, err
	}

	ski, err := subjectKeyIDFromCSR(csr)
	if err != nil {
		return nil, 0, err
	}

	cert := &x509.Certificate{
		SerialNumber:       big.NewInt(sn),
		Subject:            csr.Subject,
		NotBefore:          time.Now(),
		NotAfter:           time.Now().Add(validity),
		SignatureAlgorithm: csr.SignatureAlgorithm,
		SubjectKeyId:       ski,
		ExtKeyUsage:        []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:           x509.KeyUsageDigitalSignature,
		OCSPServer:         []string{cm.config.App.ServerHost + global.OCSPPath},
		DNSNames:           csr.DNSNames,
		IPAddresses:        csr.IPAddresses,
		EmailAddresses:     csr.EmailAddresses,
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, cert, issuer.Certificate, csr.PublicKey, issuer.PrivateKey)
	if err != nil {
		return nil, 0, err
	}
	return certBytes, cert.SerialNumber.Int64(), nil
}
