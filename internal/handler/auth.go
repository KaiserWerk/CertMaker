package handler

import (
	"fmt"
	"github.com/KaiserWerk/CertMaker/internal/dbservice"
	"github.com/KaiserWerk/CertMaker/internal/global"
	"github.com/KaiserWerk/CertMaker/internal/logging"
	"github.com/KaiserWerk/CertMaker/internal/templateservice"
	"net/http"
	"time"
)

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	var (
		logger = logging.GetLogger()
		ds = dbservice.New()
		sessMgr = global.GetSessMgr()
	)
	if r.Method == http.MethodPost {
		username := r.FormValue("username")
		password := r.FormValue("password")

		if username == "" || password == "" {
			logger.Println("username and password are required")
			http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
			return
		}

		user, err := ds.FindUser("username = ?", username)
		if err != nil {
			logger.Println("could not find user: " + err.Error())
			http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
			return
		}

		if user.Password != password {
			logger.Println("passwords did not match")
			http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
			return
		}

		sess, err := sessMgr.CreateSession(time.Now().AddDate(0,0,7))
		if err != nil {
			logger.Println("could not create session: " + err.Error())
			http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
			return
		}

		sess.SetVar("user_id", fmt.Sprintf("%d", user.ID))
		err = sessMgr.SetCookie(w, sess.Id)
		if err != nil {
			logger.Println("could not set cookie: " + err.Error())
			http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
			return
		}

		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	if err := templateservice.ExecuteTemplate(w, "auth/login.gohtml", nil); err != nil {
		w.WriteHeader(404)
	}
}

func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	var (
		sessMgr = global.GetSessMgr()
		logger = logging.GetLogger()
	)
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

	err = sessMgr.RemoveSession(sess.Id)
	if err != nil {
		logger.Println("could not remove session: " + err.Error())
		http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
		return
	}
	err = sessMgr.RemoveCookie(w)
	if err != nil {
		logger.Println("could not remove cookie: " + err.Error())
		http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
		return
	}

	http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
}

func RegistrationHandler(w http.ResponseWriter, r *http.Request) {
	if err := templateservice.ExecuteTemplate(w, "auth/registration.gohtml", nil); err != nil {
		w.WriteHeader(404)
	}
}
