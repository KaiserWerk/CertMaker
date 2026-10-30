package certmaker

import (
	"crypto/sha1"
	"crypto/x509"
	"encoding/json"

	"github.com/KaiserWerk/CertMaker/internal/entity"
)

func subjectKeyIDFromSimpleRequest(sr entity.SimpleRequest) ([]byte, error) {
	j, err := json.Marshal(sr)
	if err != nil {
		return nil, err
	}

	sum := sha1.Sum(j)
	return sum[:], nil
}

func subjectKeyIDFromCSR(csr *x509.CertificateRequest) ([]byte, error) {
	spki, err := x509.MarshalPKIXPublicKey(csr.PublicKey)
	if err != nil {
		return nil, err
	}

	sum := sha1.Sum(spki)
	return sum[:], nil
}
