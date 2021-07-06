package handler

import (
	"fmt"
	"github.com/KaiserWerk/CertMaker/internal/dbservice"
	"github.com/KaiserWerk/CertMaker/internal/entity"
	"github.com/KaiserWerk/CertMaker/internal/global"
	"github.com/KaiserWerk/CertMaker/internal/logging"
	"github.com/KaiserWerk/CertMaker/internal/security"
	"github.com/KaiserWerk/CertMaker/internal/templates"
	"net/http"
)

// ProfileHandler displays the current user's profile
func ProfileHandler(w http.ResponseWriter, r *http.Request) {
	var (
		u   = r.Context().Value("user").(entity.User)
	)

	data := struct {
		User entity.User
	}{
		User: u,
	}

	if err := templates.ExecuteTemplate(w, "user/profile.gohtml", data); err != nil {
		w.WriteHeader(http.StatusNotFound)
	}
}

// ProfileEditHandler allows profile changes to be made
func ProfileEditHandler(w http.ResponseWriter, r *http.Request) {
	var (
		logger  = logging.GetLogger().WithField("function", "ProfileEditHandler")
		ds      = dbservice.New()
		u       = r.Context().Value("user").(entity.User)
		message string
		changes uint8
	)

	if r.Method == http.MethodPost {
		form := r.FormValue("form_name")
		if form == "personal_data" {
			username := r.FormValue("username")
			if username != "" {
				_, err := ds.FindUser("username = ? AND id != ?", username, u.ID)
				if err == nil {
					message += "Username is already in use!"
				} else {
					u.Username = username
					changes++
				}
			}

			email := r.FormValue("email")
			if email != "" {
				_, err := ds.FindUser("email = ? AND id != ?", email, u.ID)
				if err == nil {
					message += "Email is already in use!"
				} else {
					u.Email = email
					changes++
				}
			}
		} else if form == "change_password" {
			newPassword1 := r.FormValue("new_password")
			newPassword2 := r.FormValue("new_password2")
			currentPassword := r.FormValue("confirm_with_password")

			if newPassword1 == "" || newPassword2 == "" || currentPassword == "" {
				logger.Debug("a new password input or the old password input is missing")
				message = "Some input was missing!"
				http.Redirect(w, r, "/user/profile/edit", http.StatusSeeOther)
				return
			}

			if newPassword1 != newPassword2 {
				logger.Debug("new password input did not match")
				message = "New password input didn't match!"
				http.Redirect(w, r, "/user/profile/edit", http.StatusSeeOther)
				return
			}

			if !security.DoesHashMatch(currentPassword, u.Password) {
				logger.Debug("old password was incorrect")
				message = "The current password was not correct!"
				http.Redirect(w, r, "/user/profile/edit", http.StatusSeeOther)
				return
			}

			hash, err := security.HashString(newPassword1)
			if err != nil {
				logger.Debug("could not hash new password: " + err.Error())
				message = "There was an error hashing your new password"
				http.Redirect(w, r, "/user/profile/edit", http.StatusSeeOther)
				return
			}
			u.Password = hash

			err = ds.UpdateUser(&u)
			if err != nil {
				logger.Debug("could not update user: " + err.Error())
				message = "There was an error setting your new password"
				http.Redirect(w, r, "/user/profile/edit", http.StatusSeeOther)
				return
			}

			message = "Password changed successfully!"
		}
	}

	message += fmt.Sprintf(" %d changes were made.", changes)

	data := struct {
		User    entity.User
		Message string
	}{
		User:    u,
		Message: message,
	}

	if err := templates.ExecuteTemplate(w, "user/profile_edit.gohtml", data); err != nil {
		w.WriteHeader(http.StatusNotFound)
	}
}

// ProfileRegenerateKeyHandler generates a new token for the current user and saves it to the DB
func ProfileRegenerateKeyHandler(w http.ResponseWriter, r *http.Request) {
	var (
		logger = logging.GetLogger().WithField("function", "handler.ProfileRegenerateKeyHandler")
		ds     = dbservice.New()
		val    = r.Context().Value("user")
		u      = val.(entity.User)
	)

	token, err := security.GenerateToken(global.ApiTokenLength)
	if err != nil {
		logger.Error("could not generate token: " + err.Error())
		http.Redirect(w, r, "/user/profile", http.StatusSeeOther)
		return
	}

	u.ApiKey = token

	err = ds.UpdateUser(&u)
	if err != nil {
		logger.Error("could not update user: " + err.Error())
		http.Redirect(w, r, "/user/profile", http.StatusSeeOther)
		return
	}

	http.Redirect(w, r, "/user/profile", http.StatusSeeOther)
}
