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

	APIPrefix = "/api/v1"

	OCSPPath                      = APIPrefix + "/ocsp"
	RootCertificateObtainPath     = APIPrefix + "/root-certificate/obtain"
	CertificateRequestPath        = APIPrefix + "/certificate/request"
	CertificateRequestWithCSRPath = APIPrefix + "/certificate/request-with-csr"
	CertificateObtainPath         = APIPrefix + "/certificate/%d/obtain"
	PrivateKeyObtainPath          = APIPrefix + "/privatekey/%d/obtain"
	SolveChallengePath            = APIPrefix + "/challenge/%d/solve"
	CertificateRevokePath         = APIPrefix + "/certificate/%d/revoke"

	WellKnownPath = "/.well-known/certmaker-challenge/token"

	RootCertificateFilename = "root-cert.pem"
	RootPrivateKeyFilename  = "root-key.pem"

	PEMContentType = "application/x-pem-file"
)

var (
	DNSNamesToSkip = []string{"localhost", "127.0.0.1", "::1", "[::1]"}
)
