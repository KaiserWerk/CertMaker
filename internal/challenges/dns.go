package challenges

import (
	"net"

	"github.com/KaiserWerk/CertMaker/internal/global"
	"github.com/KaiserWerk/CertMaker/internal/helper"
)

func CheckDNS01Challenge(domain string, expectedToken string) (bool, error) {
	// check TXT records for __certmaker_challenge.<domain> and see if expectedToken is present
	records, err := net.LookupTXT(global.DNS01ChallengeSubdomain + domain) // is a dot needed at the end?
	if err != nil {
		return false, err
	}
	if helper.StringSliceContains(records, expectedToken) {
		return true, nil
	}
	return false, nil
}
