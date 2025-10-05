package certmaker

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/KaiserWerk/CertMaker/internal/configuration"
	"github.com/KaiserWerk/CertMaker/internal/entity"
	"github.com/KaiserWerk/CertMaker/internal/global"
	"github.com/KaiserWerk/CertMaker/internal/helper"
)

var ()

type (
	Algo      string
	CertMaker struct {
		Config   *configuration.AppConfig
		snMutex  sync.Mutex
		CertFile string
		KeyFile  string
	}
)

const (
	RSA     Algo = "rsa"
	ECDSA   Algo = "ecdsa"
	ED25519 Algo = "ed25519"
)

func New(config *configuration.AppConfig) *CertMaker {
	return &CertMaker{
		Config: config,
	}
}

// SetupCA checks if root key and certificate exist. if not,
// both are created. Also check if both files are readable and
// parseable.
func (cm *CertMaker) SetupCA() error {
	cm.CertFile = filepath.Join(cm.Config.DataDir, global.RootCertificateFilename)
	cm.KeyFile = filepath.Join(cm.Config.DataDir, global.RootPrivateKeyFilename)

	if !helper.DoesFileExist(cm.CertFile) || !helper.DoesFileExist(cm.KeyFile) {
		if err := cm.GenerateRootCertAndKey(); err != nil {
			return err
		}
	}

	caFiles, err := tls.LoadX509KeyPair(cm.CertFile, cm.KeyFile)
	if err != nil {
		return err
	}
	_, err = x509.ParseCertificate(caFiles.Certificate[0])
	if err != nil {
		return err
	}

	return nil
}

// GetNextSerialNumber fetches the next serial number.
func (cm *CertMaker) GetNextSerialNumber() (int64, error) {
	cm.snMutex.Lock()
	defer cm.snMutex.Unlock()

	file := filepath.Join(cm.Config.DataDir, "sn.txt")
	cont, err := os.ReadFile(file)
	if err != nil {
		return 0, err
	}

	sn, err := strconv.ParseInt(string(cont), 10, 64)
	if err != nil {
		return 0, err
	}
	sn++

	err = os.WriteFile(file, []byte(strconv.FormatInt(sn, 10)), 0744)
	if err != nil {
		return 0, err
	}

	return sn, nil
}

// GenerateRootCertAndKey generates the root private key and with it,
// the root certificate
func (cm *CertMaker) GenerateRootCertAndKey() error {
	// create folder if it does not exist
	if err := os.MkdirAll(path.Dir(cm.CertFile), 0744); err != nil {
		return err
	}

	nextSn, err := cm.GetNextSerialNumber() // read sn from file and increment it
	if err != nil {
		return err
	}

	var (
		privKey crypto.Signer
		pubKey  crypto.PublicKey
	)

	ca := &x509.Certificate{
		SerialNumber: big.NewInt(nextSn),
		Subject: pkix.Name{
			Organization:  []string{cm.Config.RootCertSubject.Organization},
			Country:       []string{cm.Config.RootCertSubject.Country},
			Province:      []string{cm.Config.RootCertSubject.Province},
			Locality:      []string{cm.Config.RootCertSubject.Locality},
			StreetAddress: []string{cm.Config.RootCertSubject.StreetAddress},
			PostalCode:    []string{cm.Config.RootCertSubject.PostalCode},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(15, 0, 0),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	switch Algo(cm.Config.RootKeyAlgo) {
	case "":
		fallthrough
	case RSA:
		rsaPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
		if err != nil {
			return err
		}
		privKey = rsaPrivKey
		pubKey = &rsaPrivKey.PublicKey
		ca.SignatureAlgorithm = x509.SHA256WithRSA
	case ECDSA:
		ecdsaPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return err
		}
		privKey = ecdsaPrivKey
		pubKey = &ecdsaPrivKey.PublicKey
		ca.SignatureAlgorithm = x509.ECDSAWithSHA256
	case ED25519:
		edPubKey, edPrivKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		privKey = edPrivKey
		pubKey = edPubKey
		ca.SignatureAlgorithm = x509.PureEd25519
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, pubKey, privKey)
	if err != nil {
		return err
	}

	fh, err := os.OpenFile(cm.CertFile, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	err = pem.Encode(fh, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	if err != nil {
		return err
	}
	_ = fh.Close()

	fh, err = os.OpenFile(cm.KeyFile, os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	privKeyBytes, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return err
	}
	err = pem.Encode(fh, &pem.Block{Type: "PRIVATE KEY", Bytes: privKeyBytes})
	if err != nil {
		return err
	}
	_ = fh.Close()

	return nil
}

// GenerateLeafCertAndKey generates a certificate signed by
// the root certificate and a private key.
func (cm *CertMaker) GenerateLeafCertAndKey(request entity.SimpleRequest) (int64, error) {
	caTls, err := tls.LoadX509KeyPair(filepath.Join(cm.Config.DataDir, global.RootCertificateFilename), filepath.Join(cm.Config.DataDir, global.RootPrivateKeyFilename))
	if err != nil {
		panic(err)
	}
	ca, err := x509.ParseCertificate(caTls.Certificate[0])
	if err != nil {
		panic(err)
	}

	if request.Days > global.CertificateMaxDays {
		request.Days = global.CertificateMaxDays
	}

	if request.Days < global.CertificateMinDays {
		request.Days = global.CertificateMinDays
	}

	ips := make([]net.IP, 0)
	for _, v := range request.IPs {
		ip := net.ParseIP(v)
		if ip != nil {
			ips = append(ips, ip)
		}
	}

	nextSn, err := cm.GetNextSerialNumber()
	if err != nil {
		return 0, err
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
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(0, 0, request.Days),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		OCSPServer:   []string{cm.Config.ServerHost + global.OCSPPath},

		DNSNames:       request.Domains,
		IPAddresses:    ips,
		EmailAddresses: request.EmailAddresses,
	}

	_ = os.MkdirAll(fmt.Sprintf("%s/leafcerts", cm.Config.DataDir), 0744)
	outCertFilename := fmt.Sprintf("%s/leafcerts/%d-cert.pem", cm.Config.DataDir, nextSn)
	outKeyFilename := fmt.Sprintf("%s/leafcerts/%d-key.pem", cm.Config.DataDir, nextSn)

	var (
		privKey any
		pubKey  crypto.PublicKey
	)

	switch Algo(cm.Config.RootKeyAlgo) {
	case "":
		fallthrough
	case RSA:
		rsaPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
		if err != nil {
			return 0, err
		}
		privKey = rsaPrivKey
		pubKey = &rsaPrivKey.PublicKey
		cert.SignatureAlgorithm = x509.SHA256WithRSA
	case ECDSA:
		ecdsaPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return 0, err
		}
		privKey = ecdsaPrivKey
		pubKey = &ecdsaPrivKey.PublicKey
		cert.SignatureAlgorithm = x509.ECDSAWithSHA256
	case ED25519:
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return 0, err
		}
		privKey = priv
		pubKey = pub
		cert.SignatureAlgorithm = x509.PureEd25519
	}

	// Sign the certificate
	certBytes, err := x509.CreateCertificate(rand.Reader, cert, ca, pubKey, caTls.PrivateKey)
	if err != nil {
		return 0, err
	}

	// Public key + cert
	certOut, err := os.Create(outCertFilename)
	if err != nil {
		return 0, err
	}
	err = pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	if err != nil {
		return 0, err
	}
	err = certOut.Close()
	if err != nil {
		return 0, err
	}

	// Private key
	keyOut, err := os.OpenFile(outKeyFilename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0744)
	if err != nil {
		return 0, err
	}
	privKeyBytes, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return 0, err
	}
	err = pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: privKeyBytes})
	if err != nil {
		return 0, err
	}
	err = keyOut.Close()
	if err != nil {
		return 0, err
	}

	return nextSn, nil
}

func (cm *CertMaker) GenerateCertificateByCSR(csr *x509.CertificateRequest) (int64, error) {
	caTls, err := tls.LoadX509KeyPair(filepath.Join(cm.Config.DataDir, global.RootCertificateFilename), filepath.Join(cm.Config.DataDir, global.RootPrivateKeyFilename))
	if err != nil {
		return 0, err
	}
	ca, err := x509.ParseCertificate(caTls.Certificate[0])
	if err != nil {
		return 0, err
	}

	nextSn, err := cm.GetNextSerialNumber()
	if err != nil {
		return 0, err
	}

	template := &x509.Certificate{
		SerialNumber:       big.NewInt(nextSn),
		Subject:            csr.Subject,
		NotBefore:          time.Now(),
		NotAfter:           time.Now().AddDate(0, 0, global.CertificateDefaultDays),
		SubjectKeyId:       []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:        []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:           x509.KeyUsageDigitalSignature,
		SignatureAlgorithm: csr.SignatureAlgorithm,
		OCSPServer:         []string{cm.Config.ServerHost + global.OCSPPath}, // TODO implement/fix

		EmailAddresses: csr.EmailAddresses,
		DNSNames:       csr.DNSNames,
		IPAddresses:    csr.IPAddresses,
	}

	err = os.MkdirAll(filepath.Join(cm.Config.DataDir, "leafcerts"), 0744)
	if err != nil {
		return 0, err
	}
	outCertFilename := filepath.Join(cm.Config.DataDir, "leafcerts", fmt.Sprintf("%s-cert.pem", strconv.FormatInt(nextSn, 10)))

	// Sign the certificate
	certBytes, err := x509.CreateCertificate(rand.Reader, template, ca, csr.PublicKey, caTls.PrivateKey)
	if err != nil {
		return 0, err
	}

	// Public key + cert
	certOut, err := os.Create(outCertFilename)
	if err != nil {
		return 0, err
	}
	err = pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	if err != nil {
		return 0, err
	}
	err = certOut.Close()
	if err != nil {
		return 0, err
	}

	return nextSn, nil
}

// FindLeafCertificate returns the contents of the leaf certificate
// with the supplied serial number
func (cm *CertMaker) FindLeafCertificate(sn string) ([]byte, error) {
	certFile := filepath.Join(cm.Config.DataDir, "leafcerts", fmt.Sprintf("%s-cert.pem", sn))
	if !helper.DoesFileExist(certFile) {
		return nil, fmt.Errorf("cert file with id %s not found", sn)
	}

	content, err := os.ReadFile(certFile)
	if err != nil {
		return nil, err
	}

	return content, nil
}

// FindLeafPrivateKey returns the contents of the leaf private key
// with the supplied serial number
func (cm *CertMaker) FindLeafPrivateKey(sn string) ([]byte, error) {
	keyFile := filepath.Join(cm.Config.DataDir, "leafcerts", fmt.Sprintf("%s-key.pem", sn))
	if !helper.DoesFileExist(keyFile) {
		return nil, fmt.Errorf("key file with id %s not found", sn)
	}

	content, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}

	return content, nil
}

func (cm *CertMaker) GetRootCertificate() (*x509.Certificate, error) {
	certContent, err := os.ReadFile(filepath.Join(cm.Config.DataDir, "root-cert.pem"))
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(certContent)
	return x509.ParseCertificate(block.Bytes)
}

func (cm *CertMaker) GetRootKeyPair() (*x509.Certificate, crypto.Signer, error) {
	// cert
	cont, err := os.ReadFile(filepath.Join(cm.Config.DataDir, "root-cert.pem"))
	if err != nil {
		return nil, nil, err
	}

	block, _ := pem.Decode(cont)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, err
	}

	cont, err = os.ReadFile(filepath.Join(cm.Config.DataDir, "root-key.pem"))
	if err != nil {
		return nil, nil, err
	}

	block, _ = pem.Decode(cont)
	privKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, nil, err
	}

	if rsaKey, ok := privKey.(rsa.PrivateKey); ok {
		return cert, &rsaKey, nil
	}
	if ecdsaKey, ok := privKey.(ecdsa.PrivateKey); ok {
		return cert, &ecdsaKey, nil
	}
	if ed25519Key, ok := privKey.(ed25519.PrivateKey); ok {
		return cert, &ed25519Key, nil
	}

	return nil, nil, fmt.Errorf("private key is neither of type RSA, ECDSA nor ED25519")
}
