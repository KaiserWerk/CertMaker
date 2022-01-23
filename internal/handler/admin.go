package handler

import (
	"fmt"
	"github.com/KaiserWerk/CertMaker/internal/entity"
	"github.com/KaiserWerk/CertMaker/internal/global"
	"github.com/KaiserWerk/CertMaker/internal/security"
	"github.com/KaiserWerk/CertMaker/internal/templates"
	"github.com/gorilla/mux"
	"net/http"
)

// AdminSettingsHandler takes care of checking and write system-wide settings
// to the database
func (bh *BaseHandler) AdminSettingsHandler(w http.ResponseWriter, r *http.Request) {
	var (
		err    error
		logger = bh.ContextLogger("admin")
	)

	if r.Method == http.MethodPost {

		var errors uint8 = 0
		form := r.FormValue("form")

		if form == "authentication_provider" {
			authprovUserpw := "false"
			if r.FormValue("authprovider_userpw") == "true" {
				authprovUserpw = "true"
			}
			err = bh.DBSvc.SetSetting("authprovider_userpw", authprovUserpw)
			if err != nil {
				errors++
				logger.Error(err.Error())
			}

			authprovBearer := "false"
			if r.FormValue("authprovider_bearer") == "true" {
				authprovBearer = "true"
			}
			err = bh.DBSvc.SetSetting("authprovider_bearer", authprovBearer)
			if err != nil {
				errors++
				logger.Error(err.Error())
			}
		} else if form == "authentication" {
			registrationEnabled := "registration_enabled"
			if r.FormValue("registration_enabled") == "true" {
				registrationEnabled = "true"
			}
			err = bh.DBSvc.SetSetting("registration_enabled", registrationEnabled)
			if err != nil {
				errors++
				logger.Error(err.Error())
			}

			registrationRequireEmailConfirmation := "false"
			if r.FormValue("registration_require_email_confirmation") == "true" {
				registrationRequireEmailConfirmation = "true"
			}
			err = bh.DBSvc.SetSetting("registration_require_email_confirmation", registrationRequireEmailConfirmation)
			if err != nil {
				errors++
				logger.Error(err.Error())
			}
		} else if form == "certificates_and_requests" {
			certificateRevocationAllow := "false"
			if r.FormValue("certificate_revocation_allow") == "true" {
				certificateRevocationAllow = "true"
			}
			err = bh.DBSvc.SetSetting("certificate_revocation_allow", certificateRevocationAllow)
			if err != nil {
				errors++
				logger.Error(err.Error())
			}

			certificateRequestSimpleMode := "false"
			if r.FormValue("certificate_request_simple_mode") == "true" {
				certificateRequestSimpleMode = "true"
			}
			err = bh.DBSvc.SetSetting("certificate_request_simple_mode", certificateRequestSimpleMode)
			if err != nil {
				errors++
				logger.Error(err.Error())
			}

			certificateRequestNormalMode := "false"
			if r.FormValue("certificate_request_normal_mode") == "true" {
				certificateRequestNormalMode = "true"
			}
			err = bh.DBSvc.SetSetting("certificate_request_normal_mode", certificateRequestNormalMode)
			if err != nil {
				errors++
				logger.Error(err.Error())
			}

			certificateRequestKeepnocopy := "false"
			if r.FormValue("certificate_request_keepnocopy") == "true" {
				certificateRequestKeepnocopy = "true"
			}
			err = bh.DBSvc.SetSetting("certificate_request_keepnocopy", certificateRequestKeepnocopy)
			if err != nil {
				errors++
				logger.Error(err.Error())
			}

			certificateRequestRequireDomainOwnership := "false"
			if r.FormValue("certificate_request_require_domain_ownership") == "true" {
				certificateRequestRequireDomainOwnership = "true"
			}
			err = bh.DBSvc.SetSetting("certificate_request_require_domain_ownership", certificateRequestRequireDomainOwnership)
			if err != nil {
				errors++
				logger.Error(err.Error())
			}
		}

		if errors > 0 {
			logger.Errorf("When trying to save admin settings, %d error(s) occurred", errors)
		} else {
			logger.Trace("admin settings saved")
		}

		http.Redirect(w, r, "/admin/settings", http.StatusSeeOther)
		return
	}

	allSettings, err := bh.DBSvc.GetAllSettings()
	if err != nil {
		logger.Error("could not get all settings: " + err.Error())
	}

	data := struct {
		AdminSettings map[string]string
	}{
		AdminSettings: allSettings,
	}

	if err := templates.ExecuteTemplate(bh.Inj(), w, "admin/settings.gohtml", data); err != nil {
		w.WriteHeader(http.StatusNotFound)
	}
}

// AdminUserListHandler lists all existing user
func (bh *BaseHandler) AdminUserListHandler(w http.ResponseWriter, _ *http.Request) {
	var (
		logger = bh.ContextLogger("admin")
	)
	allUsers, err := bh.DBSvc.GetAllUsers()
	if err != nil {
		logger.Error("could not get all users: " + err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	data := struct {
		AllUsers []entity.User
	}{
		AllUsers: allUsers,
	}

	if err := templates.ExecuteTemplate(bh.Inj(), w, "admin/user_list.gohtml", data); err != nil {
		w.WriteHeader(http.StatusNotFound)
	}
}

// AdminUserAddHandler takes form values and creates a new user account
func (bh *BaseHandler) AdminUserAddHandler(w http.ResponseWriter, r *http.Request) {
	var (
		err    error
		logger = bh.ContextLogger("admin")
	)
	if r.Method == http.MethodPost {

		username := r.FormValue("username")
		email := r.FormValue("email")
		password := r.FormValue("password")
		password2 := r.FormValue("password2")

		if username == "" || password == "" || password2 == "" {
			logger.Debug("username and passwords required")
			http.Redirect(w, r, "/admin/user/add", http.StatusSeeOther)
			return
		}

		if password != password2 {
			logger.Debug("passwords don not match")
			http.Redirect(w, r, "/admin/user/add", http.StatusSeeOther)
			return
		}

		_, err = bh.DBSvc.FindUser("username = ?", username)
		if err == nil {
			logger.Debug("username already taken")
			http.Redirect(w, r, "/admin/user/add", http.StatusSeeOther)
			return
		}

		if email != "" {
			_, err = bh.DBSvc.FindUser("email = ?", email)
			if err == nil {
				logger.Debug("email already taken")
				http.Redirect(w, r, "/admin/user/add", http.StatusSeeOther)
				return
			}
		}

		nologin := false
		if r.FormValue("nologin") == "true" {
			nologin = true
		}

		locked := false
		if r.FormValue("locked") == "true" {
			locked = true
		}

		admin := false
		if r.FormValue("admin") == "true" {
			admin = true
		}

		apikey, err := security.GenerateToken(global.ApiTokenLength)
		if err != nil {
			logger.Error("could not generate token: " + err.Error())
			http.Redirect(w, r, "/admin/user/add", http.StatusSeeOther)
			return
		}

		hash, err := security.HashString(password)
		if err != nil {
			logger.Error("could not hash password: " + err.Error())
			http.Redirect(w, r, "/admin/user/add", http.StatusSeeOther)
			return
		}

		u := entity.User{
			Username: username,
			Email:    email,
			Password: hash,
			ApiKey:   apikey,
			NoLogin:  nologin,
			Locked:   locked,
			Admin:    admin,
		}

		err = bh.DBSvc.AddUser(&u)
		if err != nil {
			logger.Error("could not create user: " + err.Error())
			http.Redirect(w, r, "/admin/user/add", http.StatusSeeOther)
			return
		}

		logger.Trace("user added")

	}

	if err := templates.ExecuteTemplate(bh.Inj(), w, "admin/user_add.gohtml", nil); err != nil {
		w.WriteHeader(http.StatusNotFound)
	}
}

// AdminUserEditHandler allows changing values for a given user account
func (bh *BaseHandler) AdminUserEditHandler(w http.ResponseWriter, r *http.Request) {
	var (
		vars    = mux.Vars(r)
		err     error
		logger        = bh.ContextLogger("admin")
		changes uint8 = 0
		message string
	)

	userToEdit, err := bh.DBSvc.FindUser("id = ?", vars["id"])
	if err != nil {
		logger.Debug("could not find user with ID '%s': %s\n", vars["id"], err.Error())
		http.Redirect(w, r, "/admin/user/list", http.StatusSeeOther)
		return
	}

	if r.Method == http.MethodPost {
		username := r.FormValue("username")
		email := r.FormValue("email")
		password := r.FormValue("password")

		if username != "" {
			_, err = bh.DBSvc.FindUser("username = ? && id != ?", username, userToEdit.ID)
			if err == nil {
				logger.Debug("username already taken")
				http.Redirect(w, r, "/admin/user/list", http.StatusSeeOther)
				return
			}
			userToEdit.Username = username
			changes++
		}

		if email != "" {
			_, err = bh.DBSvc.FindUser("email = ? && id != ?", email, userToEdit.ID)
			if err == nil {
				logger.Debug("email already taken")
				http.Redirect(w, r, "/admin/user/list", http.StatusSeeOther)
				return
			}
			userToEdit.Email = email
			changes++
		}

		if password != "" {
			hash, err := security.HashString(password)
			if err != nil {
				logger.Error("could not hash password: " + err.Error())
				http.Redirect(w, r, "/admin/user/list", http.StatusSeeOther)
				return
			}
			userToEdit.Password = hash
			changes++
		}

		nologin := false
		if r.FormValue("nologin") == "true" {
			nologin = true
		}
		if userToEdit.NoLogin != nologin {
			changes++
			userToEdit.NoLogin = nologin
		}

		locked := false
		if r.FormValue("locked") == "true" {
			locked = true
		}
		if userToEdit.Locked != locked {
			changes++
			userToEdit.Locked = locked
		}

		admin := false
		if r.FormValue("admin") == "true" {
			admin = true
		}
		if userToEdit.Admin != admin {
			changes++
			userToEdit.Admin = admin
		}

		if changes == 0 {
			message = "No changes were made."
		} else {
			message = fmt.Sprintf("%d changes were saved!", changes)
		}

		err = bh.DBSvc.UpdateUser(&userToEdit)
		if err != nil {
			logger.Error("user data could not be updated")
			http.Redirect(w, r, "/admin/user/list", http.StatusSeeOther)
			return
		}
	}

	data := struct {
		User    entity.User
		Message string
	}{
		User:    userToEdit,
		Message: message,
	}

	if err := templates.ExecuteTemplate(bh.Inj(), w, "admin/user_edit.gohtml", data); err != nil {
		w.WriteHeader(http.StatusNotFound)
	}
}

// AdminUserRemoveHandler allows removing a given user account
func (bh *BaseHandler) AdminUserRemoveHandler(w http.ResponseWriter, r *http.Request) {
	var (
		u      = r.Context().Value("user").(entity.User)
		vars   = mux.Vars(r)
		logger = bh.ContextLogger("admin")
	)

	if fmt.Sprintf("%s", u.ID) == vars["id"] {
		logger.Debug("You cannot remove your own user account!")
		http.Redirect(w, r, "/admin/user/list", http.StatusSeeOther)
		return
	}

	user, err := bh.DBSvc.FindUser("id = ?", vars["id"])
	if err != nil {
		logger.Trace("User could not be found")
		http.Redirect(w, r, "/admin/user/list", http.StatusSeeOther)
		return
	}

	err = bh.DBSvc.DeleteUser(&user)
	if err != nil {
		logger.Error("User could not be deleted: " + err.Error())
		http.Redirect(w, r, "/admin/user/list", http.StatusSeeOther)
		return
	}

	http.Redirect(w, r, "/admin/user/list", http.StatusSeeOther)
}
