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

func HeaderMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "max-age=0, no-cache, no-store, must-revalidate")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Expires", "Thu, 01 Jan 1970 00:00:00 GMT")

		next.ServeHTTP(w, r)
	})
}

func WithSession(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc (func(w http.ResponseWriter, r *http.Request) {
		sessMgr := global.GetSessMgr()
		logger := logging.GetLogger()
		cv, err := sessMgr.GetCookieValue(r)
		if err != nil {
			logger.Println("no user-provided cookie found")
			http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
			return
		}

		sess, err := sessMgr.GetSession(cv)
		if err != nil {
			logger.Println("could not get session: " + err.Error())
			http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
			return
		}

		userId, ok := sess.GetVar("user_id")
		if !ok {
			logger.Println("session var not found")
			http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
			return
		}

		ds := dbservice.New()
		u, err := ds.FindUser("id = ?", userId)
		if err != nil && errors.Is(err, gorm.ErrRecordNotFound) {
			logger.Println("user not found: " + err.Error())
			http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
			return
		}

		ctx := context.WithValue(r.Context(), "user", u)
		cr := r.WithContext(ctx)

		next.ServeHTTP(w, cr)
	})
}

func RequireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc (func(w http.ResponseWriter, r *http.Request) {
		logger := logging.GetLogger()

		val := r.Context().Value("user")
		u := val.(entity.User)

		if !u.Admin {
			logger.Println("user " + u.Username + " is not an admin")
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}

		next.ServeHTTP(w, r)
	})
}


func WithToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {


		next.ServeHTTP(w, r)
	})
}

