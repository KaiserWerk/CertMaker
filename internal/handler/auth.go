package handler

import (
	"fmt"
	"net/http"
	"time"

	"github.com/KaiserWerk/CertMaker/internal/entity"
	"github.com/KaiserWerk/CertMaker/internal/global"
	"github.com/KaiserWerk/CertMaker/internal/security"
	"github.com/KaiserWerk/CertMaker/internal/templating"
)

// LoginHandler authenticates the user against the database, created
// a session and associates it with the user
func (bh *BaseHandler) LoginHandler(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	const template = "login.html"
	logger := bh.ContextLogger("auth")

	data := struct {
		Error   string
		Success string
		Info    string
	}{
		Error:   templating.GetErrorMessage(w, r),
		Success: templating.GetSuccessMessage(w, r),
		Info:    templating.GetInfoMessage(w, r),
	}

	if r.Method == http.MethodPost {
		username := r.FormValue("username")
		password := r.FormValue("password")

		if username == "" || password == "" {
			templating.SetErrorMessage(w, "Username and password must be supplied!")
			http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
			return
		}

		user, err := bh.DBSvc.FindUser("username = ?", username)
		if err != nil {
			templating.SetErrorMessage(w, "Could not find user.")
			http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
			return
		}

		if !security.DoesHashMatch(password, user.Password) {
			templating.SetErrorMessage(w, "Username or password incorrect.")
			http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
			return
		}

		if user.NoLogin {
			templating.SetErrorMessage(w, "This account is not allowed to login.")
			http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
			return
		}

		sess, err := bh.SessMgr.CreateSession(time.Now().AddDate(0, 0, 7))
		if err != nil {
			logger.Error("could not create session: " + err.Error())
			templating.SetErrorMessage(w, "Could not create user session.")
			http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
			return
		}

		sess.SetVar("user_id", fmt.Sprintf("%d", user.ID))
		err = bh.SessMgr.SetCookie(w, sess.Id)
		if err != nil {
			logger.Error("could not set cookie: " + err.Error())
			templating.SetErrorMessage(w, "Could not set session cookie.")
			http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
			return
		}

		templating.SetSuccessMessage(w, "You are now logged in.")
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	if err := templating.ExecuteTemplate(w, template, data); err != nil {
		logger.Errorf("could not execute template '%s': %s", template, err.Error())
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
		templating.SetErrorMessage(w, "Could not get session.")
		http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
		return
	}

	err = bh.SessMgr.RemoveSession(sess.Id)
	if err != nil {
		logger.Error("could not remove session: " + err.Error())
		templating.SetErrorMessage(w, "Could not remove session.")
		http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
		return
	}
	err = bh.SessMgr.RemoveCookie(w)
	if err != nil {
		logger.Error("could not remove cookie: " + err.Error())
		templating.SetErrorMessage(w, "Could not remove session cookie.")
		http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
		return
	}

	http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
}

// RegistrationHandler handles form values, check for validity, adds the new user
// account and optionally sends out a confirmation email
func (bh *BaseHandler) RegistrationHandler(w http.ResponseWriter, r *http.Request) {
	var (
		err      error
		template = "registration.html"
		logger   = bh.ContextLogger("auth")
	)

	if val := bh.DBSvc.GetSetting(global.SettingDisableRegistration); val == "true" {
		logger.Trace("registration is not enabled")
		http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
		return
	}

	data := struct {
		Error   string
		Success string
		Info    string
	}{
		Error:   templating.GetErrorMessage(w, r),
		Success: templating.GetSuccessMessage(w, r),
		Info:    templating.GetInfoMessage(w, r),
	}

	if r.Method == http.MethodPost {
		username := r.FormValue("username")
		email := r.FormValue("email")
		password1 := r.FormValue("password")
		password2 := r.FormValue("password2")

		if username == "" || password1 == "" || password2 == "" {
			templating.SetErrorMessage(w, "Username and passwords must be supplied.")
			http.Redirect(w, r, "/auth/register", http.StatusSeeOther)
			return
		}

		if password1 != password2 {
			templating.SetErrorMessage(w, "Passwords do not match.")
			http.Redirect(w, r, "/auth/register", http.StatusSeeOther)
			return
		}

		_, err = bh.DBSvc.FindUser("username = ?", username)
		if err == nil {
			templating.SetErrorMessage(w, "Username is already in use.")
			http.Redirect(w, r, "/auth/register", http.StatusSeeOther)
			return
		}

		_, err = bh.DBSvc.FindUser("email = ?", email)
		if err == nil {
			templating.SetErrorMessage(w, "Email address is already in use.")
			http.Redirect(w, r, "/auth/register", http.StatusSeeOther)
			return
		}

		hash, err := security.HashString(password1)
		if err != nil {
			templating.SetErrorMessage(w, "Could not hash password.")
			http.Redirect(w, r, "/auth/register", http.StatusSeeOther)
			return
		}

		u := entity.User{
			Username: username,
			Email:    email,
			Password: hash,
			NoLogin:  false,
			Locked:   false,
			Admin:    false,
		}

		err = bh.DBSvc.AddUser(&u)
		if err != nil {
			logger.Error("could not insert user: " + err.Error())
			templating.SetErrorMessage(w, "Could not add user to database.")
			http.Redirect(w, r, "/auth/register", http.StatusSeeOther)
			return
		}

		newApiKey := &entity.APIKey{
			UserID:         u.ID,
			Key:            security.GenerateToken(global.APITokenLength, u.ID),
			Name:           "Initial API Key",
			AllowedIssuers: "*",
		}
		err = bh.DBSvc.AddAPIKey(newApiKey)
		if err != nil {
			logger.Error("could not create API key: " + err.Error())
			templating.SetErrorMessage(w, "Could not create API key.")
			http.Redirect(w, r, "/admin/user/add", http.StatusSeeOther)
			return
		}

		templating.SetSuccessMessage(w, "Account created. You can now log in.")

		http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
		return
	}

	if err := templating.ExecuteTemplate(w, template, data); err != nil {
		logger.Errorf("could not execute template '%s': %s", template, err.Error())
	}
}
