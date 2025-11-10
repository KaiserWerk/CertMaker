package security

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

// GenerateToken generates a random string with a given length.
func GenerateToken(length uint8, prefix any) string {
	buf := make([]byte, length)
	_, _ = rand.Read(buf)

	if prefix == nil {
		return hex.EncodeToString(buf)
	}
	return fmt.Sprintf("%s_%s", prefix, hex.EncodeToString(buf))
}
