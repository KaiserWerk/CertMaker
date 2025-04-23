package entity

// SimpleRequest (not CSR) describes the content of a certificate request
// against the API
type SimpleRequest struct {
	Domains        []string `json:"domains"`
	IPs            []string `json:"ips"`
	EmailAddresses []string `json:"email_addresses"`
	Subject        Subject  `json:"subject,omitempty"`
	Days           int      `json:"days"`
}

type Subject struct {
	CommonName    string `json:"common_name"`
	Organization  string `json:"organization"`
	Country       string `json:"country"`
	Province      string `json:"province"`
	Locality      string `json:"locality"`
	StreetAddress string `json:"street_address"`
	PostalCode    string `json:"postal_code"`
}
