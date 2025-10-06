package handler

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/KaiserWerk/CertMaker/internal/entity"
	"github.com/KaiserWerk/CertMaker/internal/global"
	"github.com/KaiserWerk/CertMaker/internal/security"
	"github.com/KaiserWerk/CertMaker/internal/templating"

	"github.com/gorilla/mux"
)

// AdminSettingsHandler takes care of checking and write system-wide settings
// to the database
func (bh *BaseHandler) AdminSettingsHandler(w http.ResponseWriter, r *http.Request) {
	var (
		template = "system_settings.html"
		logger   = bh.ContextLogger("admin")
	)

	data := struct {
		Error         string
		Success       string
		Info          string
		User          *entity.User
		AdminSettings map[string]string
	}{
		Error:   templating.GetErrorMessage(w, r),
		Success: templating.GetSuccessMessage(w, r),
		Info:    templating.GetInfoMessage(w, r),
	}

	user, ok := r.Context().Value("user").(*entity.User)
	if !ok || user == nil {
		http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
		return
	}
	data.User = user

	var err error
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
	data.AdminSettings = allSettings

	if err := templating.ExecuteTemplate(w, template, data); err != nil {
		logger.Errorf("could not execute template '%s': %s", template, err)
	}
}

// AdminUserListHandler lists all existing user
func (bh *BaseHandler) AdminUserListHandler(w http.ResponseWriter, r *http.Request) {
	var (
		template = "user_list.html"
		logger   = bh.ContextLogger("admin")
	)

	data := struct {
		Error    string
		Success  string
		Info     string
		User     *entity.User
		AllUsers []entity.User
	}{
		Error:   templating.GetErrorMessage(w, r),
		Success: templating.GetSuccessMessage(w, r),
		Info:    templating.GetInfoMessage(w, r),
	}

	user, ok := r.Context().Value("user").(*entity.User)
	if !ok || user == nil {
		http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
		return
	}
	data.User = user

	allUsers, err := bh.DBSvc.GetAllUsers()
	if err != nil {
		logger.Error("could not get all users: " + err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	data.AllUsers = allUsers

	if err := templating.ExecuteTemplate(w, template, data); err != nil {
		logger.Errorf("could not execute template '%s': %s", template, err.Error())
	}
}

// AdminUserAddHandler takes form values and creates a new user account
func (bh *BaseHandler) AdminUserAddHandler(w http.ResponseWriter, r *http.Request) {
	var (
		err      error
		template = "user_form.html"
		logger   = bh.ContextLogger("admin")
	)

	data := struct {
		Error      string
		Success    string
		Info       string
		Edit       bool
		User       *entity.User
		UserToEdit *entity.User
	}{
		Error:   templating.GetErrorMessage(w, r),
		Success: templating.GetSuccessMessage(w, r),
		Info:    templating.GetInfoMessage(w, r),
		Edit:    false,
	}

	user, ok := r.Context().Value("user").(*entity.User)
	if !ok || user == nil {
		http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
		return
	}
	data.User = user

	if r.Method == http.MethodPost {

		username := r.FormValue("username")
		email := r.FormValue("email")
		password := r.FormValue("password")

		if username == "" || password == "" {
			templating.SetErrorMessage(w, "Username and password are required.")
			http.Redirect(w, r, "/admin/user/add", http.StatusSeeOther)
			return
		}

		_, err = bh.DBSvc.FindUser("username = ?", username)
		if err == nil {
			templating.SetErrorMessage(w, "Username is already taken.")
			http.Redirect(w, r, "/admin/user/add", http.StatusSeeOther)
			return
		}

		if email != "" {
			_, err = bh.DBSvc.FindUser("email = ?", email)
			if err == nil {
				templating.SetErrorMessage(w, "Email is already taken.")
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

			templating.SetErrorMessage(w, "Could not generate API token.")
			http.Redirect(w, r, "/admin/user/add", http.StatusSeeOther)
			return
		}

		hash, err := security.HashString(password)
		if err != nil {
			logger.Error("could not hash password: " + err.Error())
			templating.SetErrorMessage(w, "Could not hash password.")
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
			templating.SetErrorMessage(w, "Could not create user.")
			http.Redirect(w, r, "/admin/user/add", http.StatusSeeOther)
			return
		}

		templating.SetSuccessMessage(w, "User created successfully!")
	}

	if err := templating.ExecuteTemplate(w, template, data); err != nil {
		logger.Errorf("could not execute template '%s': %s", template, err)
	}
}

// AdminUserEditHandler allows changing values for a given user account
func (bh *BaseHandler) AdminUserEditHandler(w http.ResponseWriter, r *http.Request) {
	var (
		vars     = mux.Vars(r)
		err      error
		template       = "user_form.html"
		logger         = bh.ContextLogger("admin")
		changes  uint8 = 0
	)

	data := struct {
		Error      string
		Success    string
		Info       string
		Edit       bool
		User       *entity.User
		UserToEdit *entity.User
		Message    string
	}{
		Error:   templating.GetErrorMessage(w, r),
		Success: templating.GetSuccessMessage(w, r),
		Info:    templating.GetInfoMessage(w, r),
		Edit:    true,
	}

	user, ok := r.Context().Value("user").(*entity.User)
	if !ok || user == nil {
		http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
		return
	}
	data.User = user

	userToEdit, err := bh.DBSvc.FindUser("id = ?", vars["id"])
	if err != nil {
		logger.Debugf("could not find user with ID '%s': %s", vars["id"], err.Error())
		templating.SetErrorMessage(w, "User not found.")
		http.Redirect(w, r, "/admin/user/list", http.StatusSeeOther)
		return
	}
	data.UserToEdit = userToEdit

	if r.Method == http.MethodPost {
		username := r.FormValue("username")
		email := r.FormValue("email")
		password := r.FormValue("password")

		if username != "" {
			_, err = bh.DBSvc.FindUser("username = ? && id != ?", username, userToEdit.ID)
			if err == nil {
				templating.SetErrorMessage(w, "Username is already taken.")
				http.Redirect(w, r, "/admin/user/list", http.StatusSeeOther)
				return
			}
			userToEdit.Username = username
			changes++
		}

		if email != "" {
			_, err = bh.DBSvc.FindUser("email = ? && id != ?", email, userToEdit.ID)
			if err == nil {
				templating.SetErrorMessage(w, "Email is already taken.")
				http.Redirect(w, r, "/admin/user/list", http.StatusSeeOther)
				return
			}
			userToEdit.Email = email
			changes++
		}

		if password != "" {
			hash, err := security.HashString(password)
			if err != nil {
				templating.SetErrorMessage(w, "Could not hash password.")
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
			data.Info = "No changes were made."
		} else if changes == 1 {
			data.Info = "One change was saved!"
		} else {
			data.Info = fmt.Sprintf("%d changes were saved!", changes)
		}

		err = bh.DBSvc.UpdateUser(userToEdit)
		if err != nil {
			logger.Error("user data could not be updated: " + err.Error())
			templating.SetErrorMessage(w, "Could not update user.")
			http.Redirect(w, r, "/admin/user/list", http.StatusSeeOther)
			return
		}
	}

	templating.SetSuccessMessage(w, "User updated successfully!")

	if err := templating.ExecuteTemplate(w, template, data); err != nil {
		logger.Errorf("could not execute template '%s': %s", template, err.Error())
	}
}

// AdminUserRemoveHandler allows removing a given user account
func (bh *BaseHandler) AdminUserRemoveHandler(w http.ResponseWriter, r *http.Request) {
	var (
		vars   = mux.Vars(r)
		logger = bh.ContextLogger("admin")
	)

	user, ok := r.Context().Value("user").(*entity.User)
	if !ok || user == nil {
		http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
		return
	}

	userID, err := strconv.ParseUint(vars["id"], 10, 64)
	if err != nil || userID < 1 {
		templating.SetErrorMessage(w, "Invalid user ID.")
		http.Redirect(w, r, "/admin/user/list", http.StatusSeeOther)
		return
	}

	if user.ID == uint(userID) {
		logger.Debugf("You cannot remove your own user account! (User ID: %d)", user.ID)
		templating.SetErrorMessage(w, "You cannot remove your own user account!")
		http.Redirect(w, r, "/admin/user/list", http.StatusSeeOther)
		return
	}

	userToDelete, err := bh.DBSvc.FindUser("id = ?", vars["id"])
	if err != nil {
		logger.Trace("User could not be found")
		templating.SetErrorMessage(w, fmt.Sprintf("User with ID %d could not be found.", userID))
		http.Redirect(w, r, "/admin/user/list", http.StatusSeeOther)
		return
	}

	err = bh.DBSvc.DeleteUser(userToDelete)
	if err != nil {
		logger.Error("User could not be deleted: " + err.Error())
		templating.SetErrorMessage(w, "User could not be deleted.")
		http.Redirect(w, r, "/admin/user/list", http.StatusSeeOther)
		return
	}

	templating.SetSuccessMessage(w, "User deleted successfully!")
	http.Redirect(w, r, "/admin/user/list", http.StatusSeeOther)
}
