package entity

type CertificateResponse struct {
	CertificatePEM string              `json:"certificate_pem,omitempty"`
	PrivateKeyPEM  string              `json:"private_key_pem,omitempty"`
	Challenges     []ChallengeResponse `json:"challenges,omitempty"`
	Error          string              `json:"error,omitempty"`
}

type ChallengeResponse struct {
	ChallengeType  string `json:"challenge_type,omitempty"`
	ChallengeID    string `json:"challenge_id,omitempty"`
	ChallengeToken string `json:"challenge_token,omitempty"`
	ValidUntil     string `json:"valid_until,omitempty"`
}
