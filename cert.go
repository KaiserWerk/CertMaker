package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"net"
	"os"
	"path"
	"strconv"
	"sync"
	"time"
)

var (
	rootMutey sync.RWMutex
	leafMutex sync.RWMutex
	snMutex sync.RWMutex
	certFile string
	keyFile string
)


func setupCA() error {
	certFile = fmt.Sprintf("%s/%s", globalConfig.DataDir, "root-cert.pem")
	keyFile = fmt.Sprintf("%s/%s", globalConfig.DataDir, "root-key.pem")

	// check if root certificate exists
	if !doesFileExist(certFile) || !doesFileExist(keyFile) {
		// if no, generate new one and save to file
		if err := generateRootCertAndKey(); err != nil {
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

func getNextSerialNumber() (int64, error) {
	snMutex.Lock()
	defer snMutex.Unlock()

	file := fmt.Sprintf("%s/sn.txt", globalConfig.DataDir)
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

func generateRootCertAndKey() error {
	// create folder if it does not exist and
	// suppress error if it exists
	_ = os.Mkdir(path.Base(certFile), 0600)

	nextSn, err := getNextSerialNumber()
	if err != nil {
		return err
	}

	privKey, err := rsa.GenerateKey(rand.Reader, 4096)
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
			Locality:      []string{"Bergisch Gladbach"},
			StreetAddress: []string{"Oberheidkamper Straße 80"},
			PostalCode:    []string{"51469"},
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
	fh, err := os.OpenFile(certFile,  os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	err = pem.Encode(fh, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	if err != nil {
		return err
	}
	_ = fh.Close()

	fh, err = os.OpenFile(keyFile, os.O_CREATE | os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	err = pem.Encode(fh, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privKey)})
	if err != nil {
		return err
	}
	_ = fh.Close()

	return nil
}



func generateLeafCertAndKey(request certificateRequest) error {
	// Load CA
	catls, err := tls.LoadX509KeyPair("ca.crt", "ca.key")
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

	ips := make([]net.IP, 1)
	for _, v := range request.IPs {
		ip := net.ParseIP(v)
		if ip != nil {
			ips = append(ips, ip)
		}
	}

	nextSn, err := getNextSerialNumber()
	if err != nil {
		return err
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
		},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(0, 0, request.Days),
		DNSNames:     request.Domains,
		IPAddresses:  ips,
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	_ = os.Mkdir(fmt.Sprintf("%s/leafcerts", globalConfig.DataDir), 0600)
	outCertFilename := fmt.Sprintf("%s/leafcerts/%s-cert.pem", globalConfig.DataDir, strconv.FormatInt(nextSn, 10))
	outKeyFilename := fmt.Sprintf("%s/leafcerts/%s-key.pem", globalConfig.DataDir, strconv.FormatInt(nextSn, 10))

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	pub := &priv.PublicKey

	// Sign the certificate
	certBytes, err := x509.CreateCertificate(rand.Reader, cert, ca, pub, catls.PrivateKey)
	if err != nil {
		return err
	}

	// Public key
	certOut, err := os.Create(outCertFilename)
	if err != nil {
		return err
	}
	err = pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	if err != nil {
		return err
	}
	err = certOut.Close()
	if err != nil {
		return err
	}

	// Private key
	keyOut, err := os.OpenFile(outKeyFilename, os.O_WRONLY | os.O_CREATE | os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	err = pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	if err != nil {
		return err
	}
	err = keyOut.Close()
	if err != nil {
		return err
	}

	return nil
}
