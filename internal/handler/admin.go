package handler

import (
	"fmt"
	"github.com/KaiserWerk/CertMaker/internal/dbservice"
	"github.com/KaiserWerk/CertMaker/internal/entity"
	"github.com/KaiserWerk/CertMaker/internal/logging"
	"github.com/KaiserWerk/CertMaker/internal/security"
	"github.com/KaiserWerk/CertMaker/internal/templateservice"
	"github.com/gorilla/mux"
	"net/http"
)

// AdminSettingsHandler takes care of checking and write system-wide settings
// to the database
func AdminSettingsHandler(w http.ResponseWriter, r *http.Request) {
	var (
		err error
		logger = logging.GetLogger()
		ds = dbservice.New()
	)

	if r.Method == http.MethodPost {

		var errors uint8 = 0
		form := r.FormValue("form")

		if form == "authentication_provider" {
			authprovUserpw := "false"
			if r.FormValue("authprovider_userpw") == "true" {
				authprovUserpw = "true"
			}
			err = ds.SetSetting("authprovider_userpw", authprovUserpw)
			if err != nil {
				errors++
				logger.Println(err.Error())
			}

			authprovBearer := "false"
			if r.FormValue("authprovider_bearer") == "true" {
				authprovBearer = "true"
			}
			err = ds.SetSetting("authprovider_bearer", authprovBearer)
			if err != nil {
				errors++
				logger.Println(err.Error())
			}
		} else if form == "authentication" {
			registrationEnabled := "registration_enabled"
			if r.FormValue("registration_enabled") == "true" {
				registrationEnabled = "true"
			}
			err = ds.SetSetting("registration_enabled", registrationEnabled)
			if err != nil {
				errors++
				logger.Println(err.Error())
			}

			registrationRequireEmailConfirmation := "false"
			if r.FormValue("registration_require_email_confirmation") == "true" {
				registrationRequireEmailConfirmation = "true"
			}
			err = ds.SetSetting("registration_require_email_confirmation", registrationRequireEmailConfirmation)
			if err != nil {
				errors++
				logger.Println(err.Error())
			}
		} else if form == "certificates_and_requests" {
			certificateRevocationAllow := "false"
			if r.FormValue("certificate_revocation_allow") == "true" {
				certificateRevocationAllow = "true"
			}
			err = ds.SetSetting("certificate_revocation_allow", certificateRevocationAllow)
			if err != nil {
				errors++
				logger.Println(err.Error())
			}

			certificateRevocationOnlyByRequester := "false"
			if r.FormValue("certificate_revocation_only_by_requester") == "true" {
				certificateRevocationOnlyByRequester = "true"
			}
			err = ds.SetSetting("certificate_revocation_only_by_requester", certificateRevocationOnlyByRequester)
			if err != nil {
				errors++
				logger.Println(err.Error())
			}

			certificateRevocationRequireReasonphrase := "false"
			if r.FormValue("certificate_revocation_require_reasonphrase") == "true" {
				certificateRevocationRequireReasonphrase = "true"
			}
			err = ds.SetSetting("certificate_revocation_require_reasonphrase", certificateRevocationRequireReasonphrase)
			if err != nil {
				errors++
				logger.Println(err.Error())
			}

			certificateRequestSimpleMode := "false"
			if r.FormValue("certificate_request_simple_mode") == "true" {
				certificateRequestSimpleMode = "true"
			}
			err = ds.SetSetting("certificate_request_simple_mode", certificateRequestSimpleMode)
			if err != nil {
				errors++
				logger.Println(err.Error())
			}

			certificateRequestNormalMode := "false"
			if r.FormValue("certificate_request_normal_mode") == "true" {
				certificateRequestNormalMode = "true"
			}
			err = ds.SetSetting("certificate_request_normal_mode", certificateRequestNormalMode)
			if err != nil {
				errors++
				logger.Println(err.Error())
			}

			certificateRequestKeepnocopy := "false"
			if r.FormValue("certificate_request_keepnocopy") == "true" {
				certificateRequestKeepnocopy = "true"
			}
			err = ds.SetSetting("certificate_request_keepnocopy", certificateRequestKeepnocopy)
			if err != nil {
				errors++
				logger.Println(err.Error())
			}

			certificateRequestRequireDomainOwnership := "false"
			if r.FormValue("certificate_request_require_domain_ownership") == "true" {
				certificateRequestRequireDomainOwnership = "true"
			}
			err = ds.SetSetting("certificate_request_require_domain_ownership", certificateRequestRequireDomainOwnership)
			if err != nil {
				errors++
				logger.Println(err.Error())
			}
		}

		if errors > 0 {
			output := fmt.Sprintf("When trying to save admin settings, %d error(s) occurred", errors)
			logger.Println(output)
		} else {
			logger.Println("admin settings saved")
		}

		http.Redirect(w, r, "/admin/settings", http.StatusSeeOther)
		return
	}

	allSettings, err := ds.GetAllSettings()
	if err != nil {
		logger.Println("could not get all settings: " + err.Error())
	}

	data := struct {
		AdminSettings map[string]string
	}{
		AdminSettings: allSettings,
	}

	if err := templateservice.ExecuteTemplate(w, "admin/settings.gohtml", data); err != nil {
		w.WriteHeader(http.StatusNotFound)
	}
}

// AdminUserListHandler lists all existing user
func AdminUserListHandler(w http.ResponseWriter, r *http.Request) {
	var (
		ds = dbservice.New()
		logger = logging.GetLogger()
	)
	allUsers, err := ds.GetAllUsers()
	if err != nil {
		logger.Println("could not get all users: " + err.Error())
		w.WriteHeader(500)
		return
	}

	data := struct {
		AllUsers []entity.User
	}{
		AllUsers: allUsers,
	}

	if err := templateservice.ExecuteTemplate(w, "admin/user_list.gohtml", data); err != nil {
		w.WriteHeader(http.StatusNotFound)
	}
}

// AdminUserAddHandler takes form values and creates a new user account
func AdminUserAddHandler(w http.ResponseWriter, r *http.Request) {
	var (
		err error
		logger = logging.GetLogger()
	)
	if r.Method == http.MethodPost {

		username := r.FormValue("username")
		email := r.FormValue("email")
		password := r.FormValue("password")
		password2 := r.FormValue("password2")

		if username == "" || password == "" || password2 == "" {
			logger.Println("username and passwords required")
			http.Redirect(w, r, "/admin/user/add", http.StatusSeeOther)
			return
		}

		if password != password2 {
			logger.Println("passwords dont match")
			http.Redirect(w, r, "/admin/user/add", http.StatusSeeOther)
			return
		}

		ds := dbservice.New()
		_, err = ds.FindUser("username = ?", username)
		if err == nil {
			logger.Println("username already taken")
			http.Redirect(w, r, "/admin/user/add", http.StatusSeeOther)
			return
		}

		if email != "" {
			_, err = ds.FindUser("email = ?", email)
			if err == nil {
				logger.Println("email already taken")
				http.Redirect(w, r, "/admin/user/add", http.StatusSeeOther)
				return
			}
		}

		apikey, err := security.GenerateToken(40)
		if err != nil {
			logger.Println("could not generate token: " + err.Error())
			http.Redirect(w, r, "/admin/user/add", http.StatusSeeOther)
			return
		}

		hash, err := security.HashString(password)
		if err != nil {
			logger.Println("could not hash password: " + err.Error())
			http.Redirect(w, r, "/admin/user/add", http.StatusSeeOther)
			return
		}

		u := entity.User{
			Username: username,
			Email:    email,
			Password: hash,
			ApiKey: apikey,
		}

		err = ds.AddUser(&u)
		if err != nil {
			logger.Println("could not create user: " + err.Error())
			http.Redirect(w, r, "/admin/user/add", http.StatusSeeOther)
			return
		}

		logger.Println("user added")

	}

	if err := templateservice.ExecuteTemplate(w, "admin/user_add.gohtml", nil); err != nil {
		w.WriteHeader(http.StatusNotFound)
	}
}

// AdminUserEditHandler allows changing values for a given user account
func AdminUserEditHandler(w http.ResponseWriter, r *http.Request) {
	var (
		vars = mux.Vars(r)
		err error
		logger = logging.GetLogger()
		changes uint8 = 0
		ds = dbservice.New()
		message string
	)

	userToEdit, err := ds.FindUser("id = ?", vars["id"])
	if err != nil {
		logger.Printf("Could not find user with ID '%s': %s\n", vars["id"], err.Error())
		http.Redirect(w, r, "/admin/user/list", http.StatusSeeOther)
		return
	}

	if r.Method == http.MethodPost {
		username := r.FormValue("username")
		email := r.FormValue("email")
		password := r.FormValue("password")

		if username != "" {
			_, err = ds.FindUser("username = ? && id != ?", username, userToEdit.ID)
			if err == nil {
				logger.Println("Username already taken")
				http.Redirect(w, r, "/admin/user/list", http.StatusSeeOther)
				return
			}
			userToEdit.Username = username
			changes++
		}

		if email != "" {
			_, err = ds.FindUser("email = ? && id != ?", email, userToEdit.ID)
			if err == nil {
				logger.Println("Email already taken")
				http.Redirect(w, r, "/admin/user/list", http.StatusSeeOther)
				return
			}
			userToEdit.Email = email
			changes++
		}

		if password != "" {
			hash, err := security.HashString(password)
			if err != nil {
				logger.Println("cloud not hash password: " + err.Error())
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

		err = ds.UpdateUser(&userToEdit)
		if err != nil {
			logger.Println("user data could not be updated")
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

	if err := templateservice.ExecuteTemplate(w, "admin/user_edit.gohtml", data); err != nil {
		w.WriteHeader(http.StatusNotFound)
	}
}

// AdminUserRemoveHandler allows removing a given user account
func AdminUserRemoveHandler(w http.ResponseWriter, r *http.Request) {
	var (
		val = r.Context().Value("user")
		u = val.(entity.User)
		vars = mux.Vars(r)
		logger = logging.GetLogger()
		ds = dbservice.New()
	)

	if fmt.Sprintf("%s", u.ID) == vars["id"] {
		logger.Println("You cannot remove your own user account!")
		http.Redirect(w, r, "/admin/user/list", http.StatusSeeOther)
		return
	}

	user, err := ds.FindUser("id = ?", vars["id"])
	if err != nil {
		logger.Println("User could not be found")
		http.Redirect(w, r, "/admin/user/list", http.StatusSeeOther)
		return
	}

	err = ds.DeleteUser(&user)
	if err != nil {
		logger.Println("User could not be deleted!")
		http.Redirect(w, r, "/admin/user/list", http.StatusSeeOther)
		return
	}

	http.Redirect(w, r, "/admin/user/list", http.StatusSeeOther)
}