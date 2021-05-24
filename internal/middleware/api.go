package middleware

import (
	"github.com/KaiserWerk/CertMaker/internal/dbservice"
	"github.com/KaiserWerk/CertMaker/internal/logging"
	"net/http"
)

// WithToken makes sure that, if enabled, a client must provide his API key
// within an HTTP header
func WithToken(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var (
			ds = dbservice.New()
			logger = logging.GetLogger()
		)
		val, err := ds.GetSetting("authprovider_bearer")
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		} else {
			if val != "true" {
				//logger.Println("authprovider userpw not enabled; redirecting")
				next.ServeHTTP(w, r)
				return
			}
		}

		token := r.Header.Get("X-Auth-Token") // Authorization: Bearer XX?
		if token == "" {
			logger.Println("missing auth header")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, err = ds.FindUser("api_key = ?", token)
		if err != nil {
			logger.Println("could not find associated user")
			w.WriteHeader(http.StatusNotFound)
			return
		}

		next.ServeHTTP(w, r)
	})
}

