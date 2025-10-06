package global

const (
	CertificateMinDays     = 1
	CertificateMaxDays     = 182
	CertificateDefaultDays = 7
	CSRUploadMaxBytes      = 50 << 10
	APITokenLength         = 40
	ChallengeTokenLength   = 80

	TokenHeader               = "X-Api-Token"
	CertificateLocationHeader = "X-Certificate-Location"
	PrivateKeyLocationHandler = "X-Privatekey-Location"
	ChallengeLocationHeader   = "X-Challenge-Location"

	APIPrefixV1 = "/api/v1"

	OCSPPath                      = APIPrefixV1 + "/ocsp"
	RootCertificateObtainPath     = APIPrefixV1 + "/root-certificate/obtain"
	CertificateRequestPath        = APIPrefixV1 + "/certificate/request"
	CertificateRequestWithCSRPath = APIPrefixV1 + "/certificate/request-with-csr"
	CertificateObtainPath         = APIPrefixV1 + "/certificate/%d/obtain"
	PrivateKeyObtainPath          = APIPrefixV1 + "/privatekey/%d/obtain"
	SolveHTTP01ChallengePath      = APIPrefixV1 + "/http-01/%d/solve"
	SolvDNS01ChallengePath        = APIPrefixV1 + "/dns-01/%d/solve"
	CertificateRevokePath         = APIPrefixV1 + "/certificate/%d/revoke"

	WellKnownPath = "/.well-known/certmaker-challenge/token"

	RootCertificateFilename = "root-cert.pem"
	RootPrivateKeyFilename  = "root-key.pem"

	PEMContentType = "application/x-pem-file"
)

var (
	DNSNamesToSkip = []string{"localhost", "127.0.0.1", "::1", "[::1]"}
)
