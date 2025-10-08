package challenges

import "net"

func CheckDNS01Challenge(domain string, expectedToken string) (bool, error) {
	// check TXT records for __certmaker_challenge.<domain> and see if expectedToken is present
	records, err := net.LookupTXT("__certmaker_challenge." + domain) // is a dot needed at the end?
	if err != nil {
		return false, err
	}
	for _, record := range records {
		if record == expectedToken {
			return true, nil
		}
	}
	return false, nil
}
