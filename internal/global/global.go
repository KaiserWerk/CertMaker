package global

const (
	CertificateMinDays     = 1
	CertificateMaxDays     = 182
	CertificateDefaultDays = 7
	CsrUploadMaxBytes      = 5 << 10
	ApiTokenLength         = 40
	ChallengeTokenLength   = 80

	TokenHeader               = "X-Api-Token"
	CertificateLocationHeader = "X-Certificate-Location"
	PrivateKeyLocationHandler = "X-Privatekey-Location"
	ChallengeLocationHeader   = "X-Challenge-Location"

	ApiPrefix = "/api/v1"

	OCSPPath                      = ApiPrefix + "/ocsp"
	RootCertificateObtainPath     = ApiPrefix + "/root-certificate/obtain"
	CertificateRequestPath        = ApiPrefix + "/certificate/request"
	CertificateRequestWithCSRPath = ApiPrefix + "/certificate/request-with-csr"
	CertificateObtainPath         = ApiPrefix + "/certificate/%d/obtain"
	PrivateKeyObtainPath          = ApiPrefix + "/privatekey/%d/obtain"
	SolveChallengePath            = ApiPrefix + "/challenge/%d/solve"
	CertificateRevokePath         = ApiPrefix + "/certificate/%d/revoke"

	WellKnownPath = "/.well-known/certmaker-challenge/token.txt"

	RootCertificateFilename = "root-cert.pem"
	RootPrivateKeyFilename  = "root-key.pem"

	PemContentType = "application/x-pem-file"
)

var (
	DnsNamesToSkip = []string{"localhost", "127.0.0.1", "::1", "[::1]"}
)
