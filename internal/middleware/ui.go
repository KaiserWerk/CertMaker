package middleware

import (
	"context"
	"errors"
	"net/http"

	"github.com/KaiserWerk/CertMaker/internal/entity"

	"gorm.io/gorm"
)

// WithSession requires the client to have a valid session
// (to be logged in)
func (mh *MWHandler) WithSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logger := mh.ContextLogger("middleware")

		val := mh.DBSvc.GetSetting("authprovider_userpw")
		if val != "true" {
			mh.Logger.WithField("authProvider", "userPw").Trace("authprovider not enabled")
			next.ServeHTTP(w, r)
			return
		}

		cv, err := mh.SessMgr.GetCookieValue(r)
		if err != nil {
			logger.Debug("no user-provided cookie found or not readable: " + err.Error())
			http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
			return
		}

		sess, err := mh.SessMgr.GetSession(cv)
		if err != nil {
			logger.Debug("could not get session: " + err.Error())
			http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
			return
		}

		userId, ok := sess.GetVar("user_id")
		if !ok {
			logger.Debug("session var not found")
			http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
			return
		}

		u, err := mh.DBSvc.FindUser("id = ?", userId)
		if err != nil && errors.Is(err, gorm.ErrRecordNotFound) {
			logger.Debug("user not found: " + err.Error())
			http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
			return
		}

		ctx := context.WithValue(r.Context(), "user", u)
		cr := r.WithContext(ctx)

		next.ServeHTTP(w, cr)
	})
}

// RequireAdmin only continues if the logged in user is an administrator
func (mh *MWHandler) RequireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logger := mh.ContextLogger("middleware")

		if userpw := mh.DBSvc.GetSetting("authprovider_userpw"); userpw != "true" {
			next.ServeHTTP(w, r)
			return
		}

		val := r.Context().Value("user")
		if val == nil {
			logger.Error("user not found in context")
			next.ServeHTTP(w, r)
			return
		}
		u := val.(entity.User)

		if !u.Admin {
			logger.Warn("user " + u.Username + " is not an admin")
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}

		next.ServeHTTP(w, r)
	})
}
