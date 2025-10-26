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
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/KaiserWerk/CertMaker/internal/entity"
	"github.com/KaiserWerk/CertMaker/internal/global"
	"github.com/KaiserWerk/CertMaker/internal/helper"
)

type (
	Algo string
	// CertMaker struct {
	// 	Config *configuration.AppConfig

	// 	CertFile string
	// 	KeyFile  string
	// 	CRLFile  string
	// }
)

const (
	RSA     Algo = "rsa"
	ECDSA   Algo = "ecdsa"
	ED25519 Algo = "ed25519"
)

var (
	snMutex = new(sync.Mutex)
)

// func New(config *configuration.AppConfig) *CertMaker {
// 	return &CertMaker{
// 		Config: config,
// 	}
// }

// SetupCA checks if root key and certificate exist. if not,
// both are created. Also check if both files are readable and
// parseable.
// func SetupCA(dataDir string) error {
// 	certFile := filepath.Join(dataDir, global.RootCertificateFilename)
// 	keyFile := filepath.Join(dataDir, global.RootPrivateKeyFilename)

// 	if !helper.DoesFileExist(cm.CertFile) || !helper.DoesFileExist(cm.KeyFile) {
// 		if err := cm.GenerateRootCertAndKey(); err != nil {
// 			return err
// 		}
// 	}

// 	caFiles, err := tls.LoadX509KeyPair(cm.CertFile, cm.KeyFile)
// 	if err != nil {
// 		return err
// 	}
// 	_, err = x509.ParseCertificate(caFiles.Certificate[0])
// 	if err != nil {
// 		return err
// 	}

// 	return nil
// }

// GetNextLeafSerialNumber fetches the next serial number.
func GetNextLeafSerialNumber(dataDir string) (int64, error) {
	snMutex.Lock()
	defer snMutex.Unlock()

	file := filepath.Join(dataDir, "sn.txt")
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
	return sn, err
}

func GetNextCRLSerialNumber(dataDir string) (int64, error) {
	snMutex.Lock()
	defer snMutex.Unlock()

	file := filepath.Join(dataDir, "crl-sn.txt")
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
	return sn, err
}

// GenerateRootCertAndKey generates the root private key and with it,
// the root certificate
func GenerateRootCertAndKey(dataDir, certFile, keyFile string, subject pkix.Name, sigAlgo x509.SignatureAlgorithm) error {
	// create folder if it does not exist
	if err := os.MkdirAll(dataDir, 0644); err != nil {
		return err
	}

	nextSn, err := GetNextLeafSerialNumber(dataDir) // read sn from file and increment it
	if err != nil {
		return err
	}

	var (
		privKey crypto.Signer
		pubKey  crypto.PublicKey
	)

	ca := &x509.Certificate{
		SerialNumber:          big.NewInt(nextSn),
		Subject:               subject,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(15, 0, 0),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	ca.SignatureAlgorithm = sigAlgo

	switch sigAlgo {
	case x509.SHA256WithRSA, x509.SHA384WithRSA, x509.SHA512WithRSA:
		rsaPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
		if err != nil {
			return err
		}
		privKey = rsaPrivKey
		pubKey = &rsaPrivKey.PublicKey
	case x509.ECDSAWithSHA256, x509.ECDSAWithSHA384, x509.ECDSAWithSHA512:
		ecdsaPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return err
		}
		privKey = ecdsaPrivKey
		pubKey = &ecdsaPrivKey.PublicKey

	case x509.PureEd25519:
		edPubKey, edPrivKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		privKey = edPrivKey
		pubKey = edPubKey
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, pubKey, privKey)
	if err != nil {
		return err
	}

	fh, err := os.OpenFile(filepath.Join(dataDir, certFile), os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	err = pem.Encode(fh, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	if err != nil {
		return err
	}
	_ = fh.Close()

	fh, err = os.OpenFile(filepath.Join(dataDir, keyFile), os.O_CREATE|os.O_WRONLY, 0600)
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
func GenerateLeafCertAndKey(dataDir, certFile, keyFile, serverHost string, sigAlgo x509.SignatureAlgorithm, request entity.SimpleRequest) (string, string, int64, error) {
	caTls, err := tls.LoadX509KeyPair(filepath.Join(dataDir, global.RootCertificateFilename), filepath.Join(dataDir, global.RootPrivateKeyFilename))
	if err != nil {
		return "", "", 0, err
	}
	ca, err := x509.ParseCertificate(caTls.Certificate[0])
	if err != nil {
		return "", "", 0, err
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

	nextSn, err := GetNextLeafSerialNumber(dataDir)
	if err != nil {
		return "", "", 0, err
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
		NotAfter:           time.Now().AddDate(0, 0, request.Days),
		SignatureAlgorithm: sigAlgo,
		SubjectKeyId:       []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:        []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:           x509.KeyUsageDigitalSignature,
		OCSPServer:         []string{serverHost + global.OCSPPath},

		DNSNames:       request.Domains,
		IPAddresses:    ips,
		EmailAddresses: request.EmailAddresses,
	}

	_ = os.MkdirAll(fmt.Sprintf("%s/leafcerts", dataDir), 0644)
	outCertFilename := fmt.Sprintf("%s/leafcerts/%d-cert.pem", dataDir, nextSn)
	outKeyFilename := fmt.Sprintf("%s/leafcerts/%d-key.pem", dataDir, nextSn)

	var (
		privKey any
		pubKey  crypto.PublicKey
	)

	switch sigAlgo {
	case x509.SHA256WithRSA, x509.SHA384WithRSA, x509.SHA512WithRSA:
		rsaPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
		if err != nil {
			return "", "", 0, err
		}
		privKey = rsaPrivKey
		pubKey = &rsaPrivKey.PublicKey
	case x509.ECDSAWithSHA256, x509.ECDSAWithSHA384, x509.ECDSAWithSHA512:
		ecdsaPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return "", "", 0, err
		}
		privKey = ecdsaPrivKey
		pubKey = &ecdsaPrivKey.PublicKey

	case x509.PureEd25519:
		edPubKey, edPrivKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return "", "", 0, err
		}
		privKey = edPrivKey
		pubKey = edPubKey
	}

	// Sign the certificate
	certBytes, err := x509.CreateCertificate(rand.Reader, cert, ca, pubKey, caTls.PrivateKey)
	if err != nil {
		return "", "", 0, err
	}

	// Public key + cert
	certOut, err := os.OpenFile(outCertFilename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return "", "", 0, err
	}
	err = pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	if err != nil {
		return "", "", 0, err
	}
	err = certOut.Close()
	if err != nil {
		return "", "", 0, err
	}

	// Private key
	keyOut, err := os.OpenFile(outKeyFilename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0744)
	if err != nil {
		return "", "", 0, err
	}
	privKeyBytes, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return "", "", 0, err
	}
	err = pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: privKeyBytes})
	if err != nil {
		return "", "", 0, err
	}
	err = keyOut.Close()
	if err != nil {
		return "", "", 0, err
	}

	return base64.StdEncoding.EncodeToString(certBytes), base64.StdEncoding.EncodeToString(privKeyBytes), nextSn, nil
}

func GenerateCertificateByCSR(dataDir, certFile, keyFile, serverHost string, csr *x509.CertificateRequest) (string, int64, error) {
	caTls, err := tls.LoadX509KeyPair(filepath.Join(dataDir, global.RootCertificateFilename), filepath.Join(dataDir, global.RootPrivateKeyFilename))
	if err != nil {
		return "", 0, err
	}
	ca, err := x509.ParseCertificate(caTls.Certificate[0])
	if err != nil {
		return "", 0, err
	}

	nextSn, err := GetNextLeafSerialNumber()
	if err != nil {
		return "", 0, err
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
		OCSPServer:         []string{serverHost + global.OCSPPath}, // TODO implement/fix

		EmailAddresses: csr.EmailAddresses,
		DNSNames:       csr.DNSNames,
		IPAddresses:    csr.IPAddresses,
	}

	err = os.MkdirAll(filepath.Join(dataDir, "leafcerts"), 0744)
	if err != nil {
		return "", 0, err
	}
	outCertFilename := filepath.Join(dataDir, "leafcerts", fmt.Sprintf("%s-cert.pem", strconv.FormatInt(nextSn, 10)))

	// Sign the certificate
	certBytes, err := x509.CreateCertificate(rand.Reader, template, ca, csr.PublicKey, caTls.PrivateKey)
	if err != nil {
		return "", 0, err
	}

	// Public key + cert
	certOut, err := os.Create(outCertFilename)
	if err != nil {
		return "", 0, err
	}
	err = pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	if err != nil {
		return "", 0, err
	}
	err = certOut.Close()
	if err != nil {
		return "", 0, err
	}

	return base64.StdEncoding.EncodeToString(certBytes), nextSn, nil
}

// FindLeafCertificate returns the contents of the leaf certificate
// with the supplied serial number
func FindLeafCertificate(dataDir string, sn int64) ([]byte, error) {
	certFile := filepath.Join(dataDir, "leafcerts", fmt.Sprintf("%d-cert.pem", sn))
	if !helper.DoesFileExist(certFile) {
		return nil, fmt.Errorf("cert file with sn %d not found", sn)
	}

	content, err := os.ReadFile(certFile)
	return content, err
}

// FindLeafPrivateKey returns the contents of the leaf private key
// with the supplied serial number
func FindLeafPrivateKey(dataDir string, sn int64) ([]byte, error) {
	keyFile := filepath.Join(dataDir, "leafcerts", fmt.Sprintf("%d-key.pem", sn))
	if !helper.DoesFileExist(keyFile) {
		return nil, fmt.Errorf("key file with sn %d not found", sn)
	}

	content, err := os.ReadFile(keyFile)
	return content, err
}

func GetRootCertificate(dataDir string) (*x509.Certificate, error) {
	certContent, err := os.ReadFile(filepath.Join(dataDir, "root-cert.pem"))
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(certContent)
	return x509.ParseCertificate(block.Bytes)
}

func GetRootKeyPair(dataDir string) (*x509.Certificate, crypto.Signer, x509.SignatureAlgorithm, error) {
	// cert
	cont, err := os.ReadFile(filepath.Join(dataDir, "root-cert.pem"))
	if err != nil {
		return nil, nil, 0, err
	}

	block, _ := pem.Decode(cont)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, 0, err
	}

	cont, err = os.ReadFile(filepath.Join(dataDir, "root-key.pem"))
	if err != nil {
		return nil, nil, 0, err
	}

	block, _ = pem.Decode(cont)
	privKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, nil, 0, err
	}

	if rsaKey, ok := privKey.(*rsa.PrivateKey); ok {
		return cert, rsaKey, x509.SHA512WithRSA, nil
	}
	if ecdsaKey, ok := privKey.(*ecdsa.PrivateKey); ok {
		return cert, ecdsaKey, x509.ECDSAWithSHA512, nil
	}
	if ed25519Key, ok := privKey.(ed25519.PrivateKey); ok {
		return cert, &ed25519Key, x509.PureEd25519, nil
	}

	return nil, nil, 0, fmt.Errorf("private key is neither of type RSA, ECDSA nor ED25519")
}

func GenerateCRL(dataDir string, revokedCertificates []x509.RevocationListEntry) error {
	// get root certificate
	issuer, signer, _, err := GetRootKeyPair(dataDir)
	if err != nil {
		return err
	}

	sn, err := GetNextCRLSerialNumber(dataDir)
	if err != nil {
		return err
	}

	now := time.Now().UTC()
	tmpl := &x509.RevocationList{
		Number:                    big.NewInt(sn),
		ThisUpdate:                now,
		NextUpdate:                now.Add(7 * 24 * time.Hour),
		RevokedCertificateEntries: revokedCertificates,
		// optionale ExtraExtensions: z.B. AuthorityKeyId (wird automatisch aus issuer.PublicKeyId gesetzt)
		ExtraExtensions: nil,
	}

	derBytes, err := x509.CreateRevocationList(rand.Reader, tmpl, issuer, signer)
	if err != nil {
		fmt.Fprintf(os.Stderr, "CreateRevocationList failed: %v\n", err)
		os.Exit(2)
	}

	// Write PEM
	f, err := os.Create(filepath.Join(dataDir, global.CRLFile))
	if err != nil {
		panic(err)
	}
	defer f.Close()

	return pem.Encode(f, &pem.Block{Type: "X509 CRL", Bytes: derBytes})
}
