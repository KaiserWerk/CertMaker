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
	"github.com/KaiserWerk/SimpleCA/internal/entity"
	"github.com/KaiserWerk/SimpleCA/internal/global"
	"github.com/KaiserWerk/SimpleCA/internal/helper"
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

	err = ioutil.WriteFile(file, []byte(strconv.FormatInt(sn, 10)), 0600)
	if err != nil {
		return 0, err
	}

	return sn, nil
}

func GenerateRootCertAndKey() error {
	// create folder if it does not exist
	_ = os.Mkdir(path.Dir(certFile), 0700)

	nextSn, err := GetNextSerialNumber()
	if err != nil {
		return err
	}

	//privKey, err := rsa.GenerateKey(rand.Reader, 4096)
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	pubKey := &privKey.PublicKey

	ca := &x509.Certificate{
		SerialNumber: big.NewInt(nextSn), // read sn from file an increment it
		Subject: pkix.Name{
			Organization:  []string{"KaiserWerk CA ROOT"},
			Country:       []string{"DE"},
			Province:      []string{"NRW"},
			Locality:      []string{"Musterort"},
			StreetAddress: []string{"Musterstraße 1337"},
			PostalCode:    []string{"12345"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(30, 0, 0),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, pubKey, privKey)
	if err != nil {
		return err
	}

	fh, err := os.OpenFile(certFile, os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	err = pem.Encode(fh, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	if err != nil {
		return err
	}
	_ = fh.Close()

	fh, err = os.OpenFile(keyFile, os.O_CREATE|os.O_WRONLY, 0600)
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

func GenerateLeafCertAndKey(request entity.CertificateRequest) (int64, error) {
	config := global.GetConfiguration()
	catls, err := tls.LoadX509KeyPair(filepath.Join(config.DataDir, "root-cert.pem"), filepath.Join(config.DataDir, "root-key.pem"))
	if err != nil {
		panic(err)
	}
	ca, err := x509.ParseCertificate(catls.Certificate[0])
	if err != nil {
		panic(err)
	}

	if request.Days > 182 {
		request.Days = 182
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
			Organization:  []string{request.Subject.Organization},
			Country:       []string{request.Subject.Country},
			Province:      []string{request.Subject.Province},
			Locality:      []string{request.Subject.Locality},
			StreetAddress: []string{request.Subject.StreetAddress},
			PostalCode:    []string{request.Subject.PostalCode},
			//SerialNumber: "hallo 123",

		},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(0, 0, request.Days),
		DNSNames:     request.Domains,
		IPAddresses:  ips,
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		//PublicKeyAlgorithm: ,
		//SignatureAlgorithm: x509.SHA256WithRSA,
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		OCSPServer: []string{"http://localhost:8880/api/ocsp", "http://codework.me:8000/"}, // TODO implement/fix
	}

	_ = os.Mkdir(fmt.Sprintf("%s/leafcerts", config.DataDir), 0700)
	outCertFilename := fmt.Sprintf("%s/leafcerts/%s-cert.pem", config.DataDir, strconv.FormatInt(nextSn, 10))
	outKeyFilename := fmt.Sprintf("%s/leafcerts/%s-key.pem", config.DataDir, strconv.FormatInt(nextSn, 10))

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	//priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return 0, err
	}
	pub := &priv.PublicKey

	// Sign the certificate
	certBytes, err := x509.CreateCertificate(rand.Reader, cert, ca, pub, catls.PrivateKey)
	if err != nil {
		return 0, err
	}

	//caCertBytes, err := ioutil.ReadFile(fmt.Sprintf("%s/root-cert.pem", globalConfig.DataDir))
	//if err != nil {
	//	return 0, err
	//}
	//b := append(certBytes, caCertBytes...)

	// Public key
	certOut, err := os.Create(outCertFilename)
	if err != nil {
		return 0, err
	}
	err = pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	if err != nil {
		return 0, err
	}
	//err = pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: caCertBytes})
	//if err != nil {
	//	return 0, err
	//}
	err = certOut.Close()
	if err != nil {
		return 0, err
	}

	// Private key
	keyOut, err := os.OpenFile(outKeyFilename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
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
