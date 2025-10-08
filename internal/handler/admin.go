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

		SettingDisableRegistration                    string
		SettingRequireEmailConfirmationOnRegistration string
		SettingEnableSimpleRequestMode                string
		SettingEnableCSRRequestMode                   string
		SettingDisableFileRetention                   string
		SettingEnableHTTP01Challenge                  string
		SettingEnableDNS01Challenge                   string
	}{
		Error:   templating.GetErrorMessage(w, r),
		Success: templating.GetSuccessMessage(w, r),
		Info:    templating.GetInfoMessage(w, r),

		SettingDisableRegistration:                    global.SettingDisableRegistration,
		SettingRequireEmailConfirmationOnRegistration: global.SettingRequireEmailConfirmationOnRegistration,
		SettingEnableSimpleRequestMode:                global.SettingEnableSimpleRequestMode,
		SettingEnableCSRRequestMode:                   global.SettingEnableCSRRequestMode,
		SettingDisableFileRetention:                   global.SettingDisableFileRetention,
		SettingEnableHTTP01Challenge:                  global.SettingEnableHTTP01Challenge,
		SettingEnableDNS01Challenge:                   global.SettingEnableDNS01Challenge,
	}

	user, ok := r.Context().Value("user").(*entity.User)
	if !ok || user == nil {
		http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
		return
	}
	data.User = user

	var err error
	if r.Method == http.MethodPost {
		var changes uint8
		form := r.FormValue("form")
		var infoMessage, errorMessage string

		if form == "authentication" {
			registrationDisabled := global.ValueFalse
			if r.FormValue(global.SettingDisableRegistration) == global.ValueTrue {
				registrationDisabled = global.ValueTrue
			}
			// only update when changed
			if bh.DBSvc.GetSetting(global.SettingDisableRegistration) != registrationDisabled {
				changes++
				err = bh.DBSvc.SetSetting(global.SettingDisableRegistration, registrationDisabled)
				if err != nil {
					errorMessage += "Could not update 'Disable user account registration' setting. "
				} else {
					infoMessage += "'Disable user account registration' setting updated. "
				}
			}

			registrationRequireEmailConfirmation := global.ValueFalse
			if r.FormValue(global.SettingRequireEmailConfirmationOnRegistration) == global.ValueTrue {
				registrationRequireEmailConfirmation = global.ValueTrue
			}
			// only update when changed
			if bh.DBSvc.GetSetting(global.SettingRequireEmailConfirmationOnRegistration) != registrationRequireEmailConfirmation {
				changes++
				err = bh.DBSvc.SetSetting(global.SettingRequireEmailConfirmationOnRegistration, registrationRequireEmailConfirmation)
				if err != nil {
					errorMessage += "Could not update 'Require email confirmation for registration' setting. "
				} else {
					infoMessage += "'Require email confirmation for registration' setting updated. "
				}
			}
		} else if form == "certificates_and_requests" {

			certificateRequestSimpleMode := global.ValueFalse
			if r.FormValue(global.SettingEnableSimpleRequestMode) == global.ValueTrue {
				certificateRequestSimpleMode = global.ValueTrue
			}
			// only update when changed
			if bh.DBSvc.GetSetting(global.SettingEnableSimpleRequestMode) != certificateRequestSimpleMode {
				changes++
				err = bh.DBSvc.SetSetting(global.SettingEnableSimpleRequestMode, certificateRequestSimpleMode)
				if err != nil {
					errorMessage += "Could not update 'Simple Request Mode' setting. "
				} else {
					infoMessage += "'Simple Request Mode' setting updated. "
				}
			}

			certificateRequestNormalMode := global.ValueFalse
			if r.FormValue(global.SettingEnableCSRRequestMode) == global.ValueTrue {
				certificateRequestNormalMode = global.ValueTrue
			}
			// only update when changed
			if bh.DBSvc.GetSetting(global.SettingEnableCSRRequestMode) != certificateRequestNormalMode {
				changes++
				err = bh.DBSvc.SetSetting(global.SettingEnableCSRRequestMode, certificateRequestNormalMode)
				if err != nil {
					errorMessage += "Could not update 'CSR Mode' setting. "
				} else {
					infoMessage += "'CSR Mode' setting updated. "
				}
			}

			certificateRequestKeepnocopy := global.ValueFalse
			if r.FormValue(global.SettingDisableFileRetention) == global.ValueTrue {
				certificateRequestKeepnocopy = global.ValueTrue
			}
			// only update when changed
			if bh.DBSvc.GetSetting(global.SettingDisableFileRetention) != certificateRequestKeepnocopy {
				changes++
				err = bh.DBSvc.SetSetting(global.SettingDisableFileRetention, certificateRequestKeepnocopy)
				if err != nil {
					errorMessage += "Could not update 'Disable file retention' setting. "
				} else {
					infoMessage += "'Disable file retention' setting updated. "
				}
			}

			enableHTTP01Challenge := global.ValueFalse
			if r.FormValue(global.SettingEnableHTTP01Challenge) == global.ValueTrue {
				enableHTTP01Challenge = global.ValueTrue
			}

			// only update when changed
			if bh.DBSvc.GetSetting(global.SettingEnableHTTP01Challenge) != enableHTTP01Challenge {
				changes++
				err = bh.DBSvc.SetSetting(global.SettingEnableHTTP01Challenge, enableHTTP01Challenge)
				if err != nil {
					errorMessage += "Could not update 'Enable HTTP-01 challenge' setting. "
				} else {
					infoMessage += "'Enable HTTP-01 challenge' setting updated. "
				}
			}

			enableDNS01Challenge := global.ValueFalse
			if r.FormValue(global.SettingEnableDNS01Challenge) == global.ValueTrue {
				enableDNS01Challenge = global.ValueTrue
			}

			// only update when changed
			if bh.DBSvc.GetSetting(global.SettingEnableDNS01Challenge) != enableDNS01Challenge {
				changes++
				err = bh.DBSvc.SetSetting(global.SettingEnableDNS01Challenge, enableDNS01Challenge)
				if err != nil {
					errorMessage += "Could not update 'Enable DNS-01 challenge' setting. "
				} else {
					infoMessage += "'Enable DNS-01 challenge' setting updated. "
				}
			}
		}

		if errorMessage != "" {
			templating.SetErrorMessage(w, errorMessage)
		}
		if infoMessage != "" {
			templating.SetInfoMessage(w, infoMessage)
		}

		if errorMessage == "" && infoMessage == "" && changes == 0 {
			templating.SetInfoMessage(w, "No changes were made.")
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

		apikey := security.GenerateToken(global.APITokenLength)

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
