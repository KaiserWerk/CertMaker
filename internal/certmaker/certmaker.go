package certmaker

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"github.com/KaiserWerk/CertMaker/internal/dbservice"
	"github.com/KaiserWerk/CertMaker/internal/entity"
	"github.com/KaiserWerk/CertMaker/internal/global"
	"github.com/KaiserWerk/CertMaker/internal/helper"
	"io/ioutil"
	"math/big"
	"net"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

var (
	rootMutex sync.RWMutex
	leafMutex sync.RWMutex
	snMutex   sync.RWMutex
	certFile  string
	keyFile   string
)

// SetupCA checks if root key and certificate exist. if not,
// both are created. Also check if both files are readable and
// parseable.
func SetupCA() error {
	config := global.GetConfiguration()

	certFile = filepath.Join(config.DataDir, "root-cert.pem")
	keyFile = filepath.Join(config.DataDir, "root-key.pem")

	// check if root certificate exists
	if !helper.DoesFileExist(certFile) || !helper.DoesFileExist(keyFile) {
		// if no, generate new one and save to file
		if err := GenerateRootCertAndKey(); err != nil {
			return err
		}
	}

	// if yes, try to load it. return error, if any
	caFiles, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return err
	}
	// parse the content
	_, err = x509.ParseCertificate(caFiles.Certificate[0])
	if err != nil {
		return err
	}

	return nil
}

// GetNextSerialNumber fetches the next serial number.
func GetNextSerialNumber() (int64, error) {
	config := global.GetConfiguration()

	snMutex.Lock()
	defer snMutex.Unlock()

	file := fmt.Sprintf("%s/sn.txt", config.DataDir)
	cont, err := ioutil.ReadFile(file)
	if err != nil {
		return 0, err
	}

	sn, err := strconv.ParseInt(string(cont), 10, 64)
	if err != nil {
		return 0, err
	}
	sn++

	err = ioutil.WriteFile(file, []byte(strconv.FormatInt(sn, 10)), 0744)
	if err != nil {
		return 0, err
	}

	return sn, nil
}

// GenerateRootCertAndKey generates the root private key and with it,
// the root certificate
func GenerateRootCertAndKey() error {
	// create folder if it does not exist
	_ = os.Mkdir(path.Dir(certFile), 0744)

	nextSn, err := GetNextSerialNumber() // read sn from file and increment it
	if err != nil {
		return err
	}

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	pubKey := &privKey.PublicKey

	ca := &x509.Certificate{
		SerialNumber: big.NewInt(nextSn),
		Subject: pkix.Name{
			Organization:  []string{"KaiserWerk CA ROOT"},
			Country:       []string{"DE"},
			Province:      []string{"NRW"},
			Locality:      []string{"Musterort"},
			StreetAddress: []string{"Musterstraße 1337"},
			PostalCode:    []string{"12345"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(15, 0, 0),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, pubKey, privKey)
	if err != nil {
		return err
	}

	fh, err := os.OpenFile(certFile, os.O_CREATE|os.O_WRONLY, 0744)
	if err != nil {
		return err
	}
	err = pem.Encode(fh, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	if err != nil {
		return err
	}
	_ = fh.Close()

	fh, err = os.OpenFile(keyFile, os.O_CREATE|os.O_WRONLY, 0700)
	if err != nil {
		return err
	}
	privKeyBytes, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		return err
	}
	err = pem.Encode(fh, &pem.Block{Type: "EC PRIVATE KEY", Bytes: privKeyBytes})
	if err != nil {
		return err
	}
	_ = fh.Close()

	return nil
}

// GenerateLeafCertAndKey generates a certificate signed by
// the root certificate and a private key.
func GenerateLeafCertAndKey(request entity.CertificateRequest) (int64, error) {
	config := global.GetConfiguration()
	caTls, err := tls.LoadX509KeyPair(filepath.Join(config.DataDir, "root-cert.pem"), filepath.Join(config.DataDir, "root-key.pem"))
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

	nextSn, err := GetNextSerialNumber()
	if err != nil {
		return 0, err
	}

	cert := &x509.Certificate{
		SerialNumber: big.NewInt(nextSn),
		Subject: pkix.Name{
			Country:            []string{request.Subject.Country},
			Organization:       []string{request.Subject.Organization},
			Locality:           []string{request.Subject.Locality},
			Province:           []string{request.Subject.Province},
			StreetAddress:      []string{request.Subject.StreetAddress},
			PostalCode:         []string{request.Subject.PostalCode},
		},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(0, 0, request.Days),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		OCSPServer: []string{config.ServerHost + "/api/ocsp"}, // TODO implement/fix

		DNSNames:     request.Domains,
		IPAddresses:  ips,
		EmailAddresses: request.EmailAddresses,
	}

	_ = os.MkdirAll(fmt.Sprintf("%s/leafcerts", config.DataDir), 0744)
	outCertFilename := fmt.Sprintf("%s/leafcerts/%s-cert.pem", config.DataDir, strconv.FormatInt(nextSn, 10))
	outKeyFilename := fmt.Sprintf("%s/leafcerts/%s-key.pem", config.DataDir, strconv.FormatInt(nextSn, 10))

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return 0, err
	}
	pub := &priv.PublicKey

	// Sign the certificate
	certBytes, err := x509.CreateCertificate(rand.Reader, cert, ca, pub, caTls.PrivateKey)
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
	privKeyBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return 0, err
	}
	err = pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: privKeyBytes})
	if err != nil {
		return 0, err
	}
	err = keyOut.Close()
	if err != nil {
		return 0, err
	}

	return nextSn, nil
}

func GenerateKeyPairByCSR(csr *x509.CertificateRequest) (int64, error) {
	var (
		config = global.GetConfiguration()
		ds = dbservice.New()
	)

	nextSn, err := GetNextSerialNumber()
	if err != nil {
		return 0, err
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(nextSn),
		Subject: csr.Subject,
		NotBefore: time.Now(),
		NotAfter: time.Now().AddDate(0, 0, 30),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		OCSPServer: []string{config.ServerHost + "/api/ocsp"}, // TODO implement/fix

		EmailAddresses: csr.EmailAddresses,
		DNSNames: csr.DNSNames,
		IPAddresses: csr.IPAddresses,
	}

	
}

// FindLeafCertificate returns the contents of the leaf certificate
// with the supplied ID
func FindLeafCertificate(id string) ([]byte, error) {
	config := global.GetConfiguration()
	certFile := filepath.Join(config.DataDir, "leafcerts", fmt.Sprintf("%s-cert.pem", id))
	if !helper.DoesFileExist(certFile) {
		return nil, fmt.Errorf("cert file with id %s not found", id)
	}

	content, err := ioutil.ReadFile(certFile)
	if err != nil {
		return nil, err
	}

	return content, nil
}

// FindLeafPrivateKey returns the contents of the leaf private key
// with the supplied ID
func FindLeafPrivateKey(id string) ([]byte, error) {
	config := global.GetConfiguration()
	keyFile := filepath.Join(config.DataDir, "leafcerts", fmt.Sprintf("%s-key.pem", id))
	if !helper.DoesFileExist(keyFile) {
		return nil, fmt.Errorf("key file with id %s not found", id)
	}

	content, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}

	return content, nil
}