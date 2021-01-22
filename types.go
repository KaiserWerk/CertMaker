package main

type sysConf struct {
	ServerHost string `yaml:"server_host"`
	DataDir    string `yaml:"data_dir"`
}

type certificateRequest struct {
	Domains []string `json:"domains"`
	IPs     []string `json:"ips"`
	Subject struct {
		Organization  string `json:"organization"`
		Country       string `json:"country"`
		Province      string `json:"province"`
		Locality      string `json:"locality"`
		StreetAddress string `json:"street_address"`
		PostalCode    string `json:"postal_code"`
	} `json:"subject"`
	Days int `json:"days"`
}

