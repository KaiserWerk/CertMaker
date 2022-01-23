package middleware

import (
	"context"
	"net/http"
)

// WithToken makes sure that, if enabled, a client must provide his API key
// within an HTTP header
func (mh *MWHandler) WithToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logger := mh.ContextLogger("middleware")

		val := mh.DBSvc.GetSetting("authprovider_bearer")
		if val != "true" {
			logger.Debug("authprovider userpw not enabled; redirecting")
			next.ServeHTTP(w, r)
			return
		}

		token := r.Header.Get("X-Auth-Token")
		if token == "" {
			logger.Print("missing auth header")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		u, err := mh.DBSvc.FindUser("api_key = ?", token)
		if err != nil {
			logger.Print("could not find associated user")
			w.WriteHeader(http.StatusNotFound)
			return
		}

		ctx := context.WithValue(r.Context(), "user", u)
		cr := r.WithContext(ctx)

		next.ServeHTTP(w, cr)
	})
}
