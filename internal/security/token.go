package security

import (
	"crypto/rand"
	"encoding/hex"
)

// GenerateToken generates a random string with a given length.
func GenerateToken(length uint8) string {
	buf := make([]byte, length)
	_, _ = rand.Read(buf)

	return hex.EncodeToString(buf)
}
