package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"strconv"
	"sync"
	"time"
)

const (
	dataDir = "data"
)

var (
	rootMutey sync.RWMutex
	leafMutex sync.RWMutex
	snMutex sync.RWMutex
)

func getNextSerialNumber() (int64, error) {
	snMutex.Lock()
	defer snMutex.Unlock()

	file := fmt.Sprintf("%s/sn.txt", dataDir)
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

func generateRootCertAndKey(dir, certFileName, keyFileName string) error {
	certFile := fmt.Sprintf("%s/%s", dir, certFileName)
	keyFile := fmt.Sprintf("%s/%s", dir, keyFileName)

	// create folder if it does not exist and
	// suppress error if it exists
	_ = os.Mkdir(dir, 0600)

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



func generateLeafCertAndKey() ([]byte, []byte, error) {

	return nil, nil, nil
}
