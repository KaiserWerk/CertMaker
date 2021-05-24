package entity

// CertificateRequest (not CSR) describes the content of a certificate request
// against the API
type CertificateRequest struct {
	Domains []string `json:"domains"`
	IPs     []string `json:"ips"`
	Subject struct {
		Organization  string `json:"organization"`
		Country       string `json:"country"`
		Province      string `json:"province"`
		Locality      string `json:"locality"`
		StreetAddress string `json:"street_address"`
		PostalCode    string `json:"postal_code"`
	} `json:"subject,omitempty"`
	Days int `json:"days"`
}
