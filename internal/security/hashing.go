package security

import "golang.org/x/crypto/bcrypt"

// HashString returns the bcrypt hash for a given string
//
// Maybe web should use a more recent method, no?
func HashString(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	return string(bytes), err
}

// DoesHashMatch checks whether a given password and hash match
func DoesHashMatch(password string, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}
