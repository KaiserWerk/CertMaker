package middleware

import (
	"context"
	"errors"
	"github.com/KaiserWerk/CertMaker/internal/dbservice"
	"github.com/KaiserWerk/CertMaker/internal/entity"
	"github.com/KaiserWerk/CertMaker/internal/global"
	"github.com/KaiserWerk/CertMaker/internal/logging"
	"gorm.io/gorm"
	"net/http"
)

// WithSession requires the client to have a valid session
// (to be logged in)
func WithSession(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc (func(w http.ResponseWriter, r *http.Request) {
		var (
			sessMgr = global.GetSessMgr()
			logger = logging.GetLogger().WithField("function", "middleware.RequireAdmin")
			ds = dbservice.New()
		)

		val, err := ds.GetSetting("authprovider_userpw")
		if err != nil {
			logger.Errorln("could not get authentication provider setting: " + err.Error())
			http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
			return
		} else {
			if val != "true" {
				//logger.Println("authprovider userpw not enabled; redirecting")
				next.ServeHTTP(w, r)
				return
			}
		}

		cv, err := sessMgr.GetCookieValue(r)
		if err != nil {
			logger.Debugln("no user-provided cookie found or not readable: " + err.Error())
			http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
			return
		}

		sess, err := sessMgr.GetSession(cv)
		if err != nil {
			logger.Debugln("could not get session: " + err.Error())
			http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
			return
		}

		userId, ok := sess.GetVar("user_id")
		if !ok {
			logger.Debugln("session var not found")
			http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
			return
		}


		u, err := ds.FindUser("id = ?", userId)
		if err != nil && errors.Is(err, gorm.ErrRecordNotFound) {
			logger.Debugln("user not found: " + err.Error())
			http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
			return
		}

		ctx := context.WithValue(r.Context(), "user", u)
		cr := r.WithContext(ctx)

		next.ServeHTTP(w, cr)
	})
}

// RequireAdmin only continues if the logged in user is an administrator
func RequireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc (func(w http.ResponseWriter, r *http.Request) {
		logger := logging.GetLogger().WithField("function", "middleware.RequireAdmin")

		val := r.Context().Value("user")
		if val == nil {
			logger.Errorln("user not found in context")
			next.ServeHTTP(w, r)
			return
		}
		u := val.(entity.User)

		if !u.Admin {
			logger.Debugln("user " + u.Username + " is not an admin")
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}

		next.ServeHTTP(w, r)
	})
}
