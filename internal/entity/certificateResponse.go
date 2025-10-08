package entity

type CertificateResponse struct {
	CertificatePem  string `json:"certificate_pem,omitempty"`
	PrivateKeyPem   string `json:"private_key_pem,omitempty"`
	HTTP01Challenge string `json:"http01_challenge,omitempty"`
	DNS01Challenge  string `json:"dns01_challenge,omitempty"`
	Error           string `json:"error,omitempty"`
}
