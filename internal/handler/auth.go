package handler

import (
	"fmt"
	"github.com/KaiserWerk/CertMaker/internal/dbservice"
	"github.com/KaiserWerk/CertMaker/internal/entity"
	"github.com/KaiserWerk/CertMaker/internal/global"
	"github.com/KaiserWerk/CertMaker/internal/logging"
	"github.com/KaiserWerk/CertMaker/internal/security"
	"github.com/KaiserWerk/CertMaker/internal/templateservice"
	"net/http"
	"time"
)

// LoginHandler authenticates the user against the database, created
// a session and associates it with the user
func LoginHandler(w http.ResponseWriter, r *http.Request) {
	var (
		logger  = logging.GetLogger().WithField("function", "handler.LoginHandler")
		ds      = dbservice.New()
		sessMgr = global.GetSessMgr()
	)

	val := ds.GetSetting("authprovider_userpw")
	if val != "true" {
		//logger.Println("authprovider userpw not enabled; redirecting")
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	if r.Method == http.MethodPost {
		username := r.FormValue("username")
		password := r.FormValue("password")

		if username == "" || password == "" {
			logger.Debug("username and password are required")
			http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
			return
		}

		user, err := ds.FindUser("username = ?", username)
		if err != nil {
			logger.Debug("could not find user: " + err.Error())
			http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
			return
		}

		if !security.DoesHashMatch(password, user.Password) {
			logger.Debug("passwords did not match")
			http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
			return
		}

		sess, err := sessMgr.CreateSession(time.Now().AddDate(0, 0, 7))
		if err != nil {
			logger.Error("could not create session: " + err.Error())
			http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
			return
		}

		sess.SetVar("user_id", fmt.Sprintf("%d", user.ID))
		err = sessMgr.SetCookie(w, sess.Id)
		if err != nil {
			logger.Error("could not set cookie: " + err.Error())
			http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
			return
		}

		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	if err := templateservice.ExecuteTemplate(w, "auth/login.gohtml", nil); err != nil {
		w.WriteHeader(http.StatusNotFound)
	}
}

// LogoutHandler makes sure the user session is invalidated and
// the session cookie is removed
func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	var (
		sessMgr = global.GetSessMgr()
		logger  = logging.GetLogger().WithField("function", "handler.LogoutHandler")
	)
	cv, err := sessMgr.GetCookieValue(r)
	if err != nil {
		logger.Debug("no user-provided cookie found")
		http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
		return
	}

	sess, err := sessMgr.GetSession(cv)
	if err != nil {
		logger.Error("could not get session: " + err.Error())
		http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
		return
	}

	err = sessMgr.RemoveSession(sess.Id)
	if err != nil {
		logger.Error("could not remove session: " + err.Error())
		http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
		return
	}
	err = sessMgr.RemoveCookie(w)
	if err != nil {
		logger.Error("could not remove cookie: " + err.Error())
		http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
		return
	}

	http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
}

// RegistrationHandler handles form values, check for validity, adds the new user
// account and optionally sends out a confirmation email
func RegistrationHandler(w http.ResponseWriter, r *http.Request) {
	var (
		err    error
		logger = logging.GetLogger().WithField("function", "handler.RegistrationHandler")
		ds     = dbservice.New()
	)

	// Only comment out for debug purposes
	val := ds.GetSetting("registration_enabled")
	if val != "true" {
		logger.Trace("registration is not enabled")
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	if r.Method == http.MethodPost {
		username := r.FormValue("username")
		email := r.FormValue("email")
		password1 := r.FormValue("password")
		password2 := r.FormValue("password2")

		if username == "" || password1 == "" || password2 == "" {
			logger.Debug("Username and password must be supplied")
			http.Redirect(w, r, "/auth/register", http.StatusSeeOther)
			return
		}

		if password1 != password2 {
			logger.Debug("passwords do not match")
			http.Redirect(w, r, "/auth/register", http.StatusSeeOther)
			return
		}

		_, err = ds.FindUser("username = ?", username)
		if err == nil {
			logger.Debug("username already in use")
			http.Redirect(w, r, "/auth/register", http.StatusSeeOther)
			return
		}

		_, err = ds.FindUser("email = ?", email)
		if err == nil {
			logger.Debug("email already in use")
			http.Redirect(w, r, "/auth/register", http.StatusSeeOther)
			return
		}

		hash, err := security.HashString(password1)
		if err != nil {
			logger.Error("password could not be hashed")
			http.Redirect(w, r, "/auth/register", http.StatusSeeOther)
			return
		}

		key, err := security.GenerateToken(40)
		if err != nil {
			logger.Error("api key could not be generated")
			http.Redirect(w, r, "/auth/register", http.StatusSeeOther)
			return
		}

		u := entity.User{
			Username: username,
			Email:    email,
			Password: hash,
			ApiKey:   key,
			NoLogin:  false,
			Locked:   false,
			Admin:    false,
		}

		err = ds.AddUser(&u)
		if err != nil {
			logger.Error("could not insert user: " + err.Error())
			http.Redirect(w, r, "/auth/register", http.StatusSeeOther)
			return
		}

		http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
		return
	}

	if err := templateservice.ExecuteTemplate(w, "auth/registration.gohtml", nil); err != nil {
		w.WriteHeader(http.StatusNotFound)
	}
}
