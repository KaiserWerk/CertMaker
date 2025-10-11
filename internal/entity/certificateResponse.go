package entity

type CertificateResponse struct {
	CertificatePEM  string `json:"certificate_pem,omitempty"`
	PrivateKeyPEM   string `json:"private_key_pem,omitempty"`
	HTTP01Challenge bool   `json:"http01_challenge,omitempty"`
	DNS01Challenge  bool   `json:"dns01_challenge,omitempty"`
	ChallengeID     string `json:"challenge_id,omitempty"`
	ChallengeToken  string `json:"challenge_token,omitempty"`
	Error           string `json:"error,omitempty"`
}
