package templates

import (
	"encoding/base64"
	"net/http"
	"time"
)

func GetSuccessMessage(w http.ResponseWriter, r *http.Request) string {
	return getMessageFromCookie(w, r, global.SuccessCookieName)
}

func SetSuccessMessage(w http.ResponseWriter, message string) {
	c := &http.Cookie{
		Name:     global.SuccessCookieName,
		Value:    base64.RawURLEncoding.EncodeToString([]byte(message)),
		HttpOnly: true,
		Expires:  time.Now().Add(24 * time.Hour),
		Path:     "/",
	}
	http.SetCookie(w, c)
}

func GetErrorMessage(w http.ResponseWriter, r *http.Request) string {
	return getMessageFromCookie(w, r, global.ErrorCookieName)
}

func SetErrorMessage(w http.ResponseWriter, message string) {
	c := &http.Cookie{
		Name:     global.ErrorCookieName,
		Value:    base64.RawURLEncoding.EncodeToString([]byte(message)),
		HttpOnly: true,
		Expires:  time.Now().Add(24 * time.Hour),
		Path:     "/",
	}
	http.SetCookie(w, c)
}

func getMessageFromCookie(w http.ResponseWriter, r *http.Request, cookieName string) string {
	c, err := r.Cookie(cookieName)
	if err != nil {
		return ""
	}
	if c == nil {
		return ""
	}
	if c.Value == "" {
		removeCookie(w, cookieName)
		return ""
	}
	// Clear the cookie after reading it
	removeCookie(w, cookieName)
	v, _ := base64.RawURLEncoding.DecodeString(c.Value)
	return string(v)
}

func removeCookie(w http.ResponseWriter, cookieName string) {
	c2 := &http.Cookie{
		Name:     cookieName,
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
	}
	http.SetCookie(w, c2)
}
