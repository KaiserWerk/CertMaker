package handler

import (
	"fmt"
	"github.com/KaiserWerk/CertMaker/internal/entity"
	"github.com/KaiserWerk/CertMaker/internal/global"
	"github.com/KaiserWerk/CertMaker/internal/security"
	"github.com/KaiserWerk/CertMaker/internal/templates"
	"html/template"
	"net/http"
	"time"
)

// LoginHandler authenticates the user against the database, created
// a session and associates it with the user
func (bh *BaseHandler) LoginHandler(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	logger := bh.ContextLogger("auth")

	if val := bh.DBSvc.GetSetting("authprovider_userpw"); val != "true" {
		logger.Debug("authprovider userpw not enabled; redirecting")
		templates.SetMessage(r, templates.MsgInfo, "AuthProvider 'userpw' not enabled; redirecting...")
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	if r.Method == http.MethodPost {
		username := r.FormValue("username")
		password := r.FormValue("password")

		if username == "" || password == "" {
			logger.Debug("username and password are required")
			templates.SetMessage(r, templates.MsgInfo, "Please enter username and password!")
			http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
			return
		}

		user, err := bh.DBSvc.FindUser("username = ?", username)
		if err != nil {
			logger.Debug("could not find user: " + err.Error())
			templates.SetMessage(r, templates.MsgError, "Incorrect credentials!")
			http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
			return
		}

		if !security.DoesHashMatch(password, user.Password) {
			logger.Debug("password did not match")
			templates.SetMessage(r, templates.MsgError, "Incorrect credentials!")
			http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
			return
		}

		if user.NoLogin {
			logger.Info("user logged in correctly, but was cancelled due to nologin setting")
			templates.SetMessage(r, templates.MsgError, "No login possible due to 'nologin' setting!")
			http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
			return
		}

		sess, err := bh.SessMgr.CreateSession(time.Now().AddDate(0, 0, 7))
		if err != nil {
			logger.Error("could not create session: " + err.Error())
			templates.SetMessage(r, templates.MsgError, "Session could not be created!")
			http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
			return
		}

		sess.SetVar("user_id", fmt.Sprintf("%d", user.ID))
		err = bh.SessMgr.SetCookie(w, sess.Id)
		if err != nil {
			logger.Error("could not set cookie: " + err.Error())
			templates.SetMessage(r, templates.MsgError, "Cookie could not be set!")
			http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
			return
		}

		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	msg := templates.GetMessage(r, templates.MsgError, "ERROR!!!")
	logger.Trace("Message: ", msg)
	data := struct {
		Message template.HTML
	}{
		Message: msg,
	}

	if err := templates.ExecuteTemplate(bh.Inj(), w, "auth/login.gohtml", data); err != nil {
		w.WriteHeader(http.StatusNotFound)
	}
}

// LogoutHandler makes sure the user session is invalidated and
// the session cookie is removed
func (bh *BaseHandler) LogoutHandler(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	logger := bh.ContextLogger("auth")

	cv, err := bh.SessMgr.GetCookieValue(r)
	if err != nil {
		logger.Debug("no user-provided cookie found")
		http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
		return
	}

	sess, err := bh.SessMgr.GetSession(cv)
	if err != nil {
		logger.Error("could not get session: " + err.Error())
		http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
		return
	}

	err = bh.SessMgr.RemoveSession(sess.Id)
	if err != nil {
		logger.Error("could not remove session: " + err.Error())
		http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
		return
	}
	err = bh.SessMgr.RemoveCookie(w)
	if err != nil {
		logger.Error("could not remove cookie: " + err.Error())
		http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
		return
	}

	http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
}

// RegistrationHandler handles form values, check for validity, adds the new user
// account and optionally sends out a confirmation email
func (bh *BaseHandler) RegistrationHandler(w http.ResponseWriter, r *http.Request) {
	var (
		err    error
		logger = bh.ContextLogger("auth")
	)

	if val := bh.DBSvc.GetSetting("registration_enabled"); val != "true" {
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

		_, err = bh.DBSvc.FindUser("username = ?", username)
		if err == nil {
			logger.Debug("username already in use")
			http.Redirect(w, r, "/auth/register", http.StatusSeeOther)
			return
		}

		_, err = bh.DBSvc.FindUser("email = ?", email)
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

		key, err := security.GenerateToken(global.ApiTokenLength)
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

		err = bh.DBSvc.AddUser(&u)
		if err != nil {
			logger.Error("could not insert user: " + err.Error())
			http.Redirect(w, r, "/auth/register", http.StatusSeeOther)
			return
		}

		http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
		return
	}

	if err := templates.ExecuteTemplate(bh.Inj(), w, "auth/registration.gohtml", nil); err != nil {
		w.WriteHeader(http.StatusNotFound)
	}
}
