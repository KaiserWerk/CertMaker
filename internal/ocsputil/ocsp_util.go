package ocsputil

import (
	"crypto/x509/pkix"
	"encoding/asn1"
)

var OidOCSPNonce = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 2}

// extractNonceFromRequestDER nimmt die rohe DER-Kodierung einer OCSPRequest
// und gibt die Nonce (oder nil) zurück.
func ExtractNonceFromRequestDER(reqDER []byte) ([]byte, error) {
	// Outer OCSPRequest ::= SEQUENCE { tbsRequest TBSRequest, optionalSignature [0] EXPLICIT Signature OPTIONAL }
	var outer asn1.RawValue
	rest, err := asn1.Unmarshal(reqDER, &outer)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 {
		// optional: warnen / ignorieren extra bytes
	}

	// outer.Bytes enthält das DER der tbsRequest (weil outer is the SEQUENCE and Bytes is content)
	// Nun tbsRequest parsen. Wir definieren nur die Felder, die wir brauchen:
	//
	// TBSRequest ::= SEQUENCE {
	//   version [0] EXPLICIT Version DEFAULT v1,
	//   requestorName [1] EXPLICIT GeneralName OPTIONAL,
	//   requestList SEQUENCE OF Request,
	//   requestExtensions [2] EXPLICIT Extensions OPTIONAL
	// }
	//
	// Extensions ist eine SEQUENCE OF Extension (pkix.Extension passt sehr gut).
	type tbsRequest struct {
		// Wir brauchen requestList nur um ASN.1 Cursor richtig zu positionieren.
		// RequestList als RawValue, damit die folgende Extension (tag 2) korrekt geparst wird.
		RequestList       asn1.RawValue    `asn1:"sequence"`
		RequestExtensions []pkix.Extension `asn1:"tag:2,explicit,optional"`
	}

	var tbs tbsRequest
	_, err = asn1.Unmarshal(outer.Bytes, &tbs)
	if err != nil {
		// Manche implementierungen (oder fehlerhafte Clients) können die Reihenfolge anders kodieren.
		// Versuch: Versuche, direkt die Extensions Sequenz aus outer.Bytes zu extrahieren (robuster)
		return nil, err
	}

	// Durchsuche die Extensions nach der Nonce OID
	for _, ext := range tbs.RequestExtensions {
		if ext.Id.Equal(OidOCSPNonce) {
			// ext.Value ist per ASN.1 die OCTET STRING (extnValue), d.h. ext.Value enthält
			// typischerweise die Raw-Bytes der Nonce (manchmal als OCTET STRING verpackt).
			// Manche Implementierungen packen die Nonce nochmal in ein OCTET STRING:
			var nonce []byte
			// Versuch, ext.Value als OCTET STRING zu unmarshalen — wenn das scheitert,
			// könnte ext.Value die Nonce selbst sein.
			if _, err := asn1.Unmarshal(ext.Value, &nonce); err == nil {
				return nonce, nil
			}
			// fallback: ext.Value direkt zurückgeben
			return ext.Value, nil
		}
	}

	// keine Nonce gefunden
	return nil, nil
}

func MustASN1Marshal(val interface{}) []byte {
	b, err := asn1.Marshal(val)
	if err != nil {
		panic(err)
	}
	return b
}
