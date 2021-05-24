package security

import (
	"crypto/rand"
	"encoding/hex"
)

// GenerateToken generates a random string with a given length.
func GenerateToken(length uint8) (string, error) {
	buf := make([]byte, length)
	_, err := rand.Read(buf)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(buf), nil
}
