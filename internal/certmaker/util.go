package certmaker

import (
	"bytes"
	"crypto"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/KaiserWerk/CertMaker/internal/entity"
	"golang.org/x/crypto/ocsp"
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

func EncodeCertificateToPEM(cert *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}

func EncodePrivateKeyToPEM(privKey crypto.Signer) ([]byte, error) {
	privKeyBytes, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return nil, err
	}

	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privKeyBytes}), nil
}

func MatchesIssuer(req *ocsp.Request, ca *x509.Certificate) (bool, error) {
	if req == nil || ca == nil {
		return false, errors.New("nil request or CA certificate")
	}
	if !req.HashAlgorithm.Available() {
		return false, fmt.Errorf("Hash-Algorithmus %v nicht verfügbar", req.HashAlgorithm)
	}

	h := req.HashAlgorithm.New()

	// IssuerNameHash = Hash des DER-kodierten Subject-Namens der CA.
	_, _ = h.Write(ca.RawSubject)
	nameHash := h.Sum(nil)

	h.Reset()

	// IssuerKeyHash = Hash der subjectPublicKey-Bits, nicht der gesamten
	// SubjectPublicKeyInfo-Struktur.
	var spki struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	rest, err := asn1.Unmarshal(ca.RawSubjectPublicKeyInfo, &spki)
	if err != nil {
		return false, fmt.Errorf("SubjectPublicKeyInfo dekodieren: %w", err)
	}
	if len(rest) != 0 {
		return false, errors.New("unerwartete Restdaten in SubjectPublicKeyInfo")
	}

	_, _ = h.Write(spki.PublicKey.RightAlign())
	keyHash := h.Sum(nil)

	return bytes.Equal(nameHash, req.IssuerNameHash) &&
		bytes.Equal(keyHash, req.IssuerKeyHash), nil
}
