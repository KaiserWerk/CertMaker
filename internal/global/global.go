package global

import "time"

type RequestInfoStatus string

const (
	RequestInfoStatusAccepted RequestInfoStatus = "accepted"
	RequestInfoStatusRejected RequestInfoStatus = "rejected"
	RequestInfoStatusPending  RequestInfoStatus = "pending"
	RequestInfoStatusIssued   RequestInfoStatus = "issued"
)

const (
	CertificateMinDays     = 1
	CertificateMaxDays     = 182
	CertificateDefaultDays = 7
	CSRUploadMaxBytes      = 5 << 10 // 5 KiB
	APITokenLength         = 40
	ChallengeTokenLength   = 80

	TokenHeader = "X-Api-Token"

	APIPrefixV1                   = "/api/v1"
	OCSPPath                      = APIPrefixV1 + "/ocsp"
	RootCertificateObtainPath     = APIPrefixV1 + "/root-certificate/obtain"
	CertificateRequestPath        = APIPrefixV1 + "/certificate/request"
	CertificateRequestWithCSRPath = APIPrefixV1 + "/certificate/request-with-csr"
	CertificateObtainPath         = APIPrefixV1 + "/certificate/%d/obtain"
	PrivateKeyObtainPath          = APIPrefixV1 + "/privatekey/%d/obtain"
	SolveHTTP01ChallengePath      = APIPrefixV1 + "/http-01/%s/solve"
	SolvDNS01ChallengePath        = APIPrefixV1 + "/dns-01/%s/solve"
	CertificateRevokePath         = APIPrefixV1 + "/certificate/%d/revoke"

	WellKnownPath = "/.well-known/certmaker-challenge/token"

	RootCertificateFilename = "root-cert.pem"
	RootPrivateKeyFilename  = "root-key.pem"
	CRLFile                 = "crl.pem"

	PEMContentType = "application/x-pem-file"

	DefaultChallengeValidity                    = 2 * time.Hour
	HTTP01ChallengeDefaultValidationPort uint16 = 80

	DNS01ChallengeSubdomain = "__certmaker_challenge."
)

var (
	DNSNamesToSkip = []string{"localhost"}
	IPsToSkip      = []string{"127.0.0.1", "::1", "[::1]"}
)
