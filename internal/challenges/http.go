package challenges

import (
	"fmt"
	"io"
	"net/http"

	"github.com/KaiserWerk/CertMaker/internal/global"
)

func CheckHTTP01Challenge(client *http.Client, domain string, port uint16, expectedToken string) (bool, error) {
	if port == 0 {
		port = global.HTTP01ChallengeDefaultValidationPort
	}
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://%s:%d%s", domain, port, global.WellKnownPath), nil)
	if err != nil {
		return false, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, nil
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, err
	}

	return string(body) == expectedToken, nil
}
