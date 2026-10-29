package middleware

import (
	"context"
	"net/http"
)

// RequireToken makes sure that, if enabled, a client must provide his API key
// within an HTTP header
func (mh *MWHandler) RequireToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logger := mh.ContextLogger("middleware")

		token := r.Header.Get("X-Auth-Token")
		if token == "" {
			logger.Print("missing auth header")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		key, err := mh.DBSvc.FindAPIKey("key_content = ?", token)
		if err != nil {
			logger.Print("could not find associated API key")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		u, err := mh.DBSvc.FindUser("id = ?", key.UserID)
		if err != nil {
			logger.Print("could not find associated user")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), "user", u)
		ctx = context.WithValue(ctx, "apiKey", key)
		cr := r.WithContext(ctx)

		next.ServeHTTP(w, cr)
	})
}
