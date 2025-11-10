package handler

import (
	"fmt"
	"net/http"

	"github.com/KaiserWerk/CertMaker/internal/entity"
	"github.com/KaiserWerk/CertMaker/internal/security"
	"github.com/KaiserWerk/CertMaker/internal/templating"
)

// ProfileHandler displays the current user's profile
func (bh *BaseHandler) ProfileHandler(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	logger := bh.ContextLogger("profile")
	const template = "user_profile.html"

	data := struct {
		Error   string
		Success string
		Info    string
		User    *entity.User
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

	if err := templating.ExecuteTemplate(w, template, data); err != nil {
		logger.Errorf("could not execute template %s: %s", template, err.Error())
	}
}

// ProfileEditHandler allows profile changes to be made
func (bh *BaseHandler) ProfileEditHandler(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	const template = "user_profile_edit.html"
	var changes uint8
	logger := bh.ContextLogger("profile")

	data := struct {
		Error   string
		Success string
		Info    string
		User    *entity.User
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

	if r.Method == http.MethodPost {
		form := r.FormValue("form_name")
		if form == "personal_data" {
			username := r.FormValue("username")
			if username != "" {
				_, err := bh.DBSvc.FindUser("username = ? AND id != ?", username, user.ID)
				if err == nil {
					data.Error += "Username is already in use!"
				} else {
					user.Username = username
					changes++
				}
			}

			email := r.FormValue("email")
			if email != "" {
				_, err := bh.DBSvc.FindUser("email = ? AND id != ?", email, user.ID)
				if err == nil {
					data.Error += "Email is already in use!"
				} else {
					user.Email = email
					changes++
				}
			}

			if changes == 0 {
				data.Info = "No changes were made."
			} else if changes == 1 {
				data.Info = "One change was made."
			} else {
				data.Info = fmt.Sprintf("%d changes were made.", changes)
			}
		} else if form == "change_password" {
			newPassword1 := r.FormValue("new_password")
			newPassword2 := r.FormValue("new_password2")
			currentPassword := r.FormValue("confirm_with_password")

			if newPassword1 == "" || newPassword2 == "" || currentPassword == "" {
				logger.Debug("a new password input or the old password input is missing")
				data.Error = "Some input was missing!"
				http.Redirect(w, r, "/user/profile/edit", http.StatusSeeOther)
				return
			}

			if newPassword1 != newPassword2 {
				logger.Debug("new password input did not match")
				data.Error = "New password input didn't match!"
				http.Redirect(w, r, "/user/profile/edit", http.StatusSeeOther)
				return
			}

			if !security.DoesHashMatch(currentPassword, user.Password) {
				logger.Debug("old password was incorrect")
				data.Error = "The current password was not correct!"
				http.Redirect(w, r, "/user/profile/edit", http.StatusSeeOther)
				return
			}

			hash, err := security.HashString(newPassword1)
			if err != nil {
				logger.Debug("could not hash new password: " + err.Error())
				data.Error = "There was an error hashing your new password"
				http.Redirect(w, r, "/user/profile/edit", http.StatusSeeOther)
				return
			}
			user.Password = hash

			err = bh.DBSvc.UpdateUser(user)
			if err != nil {
				logger.Debug("could not update user: " + err.Error())
				data.Error = "There was an error setting your new password"
				http.Redirect(w, r, "/user/profile/edit", http.StatusSeeOther)
				return
			}

			data.Success = "Password changed successfully!"
		}
	}

	if err := templating.ExecuteTemplate(w, template, data); err != nil {
		logger.Errorf("could not execute template %s: %s", template, err.Error())
	}
}
