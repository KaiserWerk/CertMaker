package handler

import (
	"github.com/KaiserWerk/CertMaker/internal/dbservice"
	"github.com/KaiserWerk/CertMaker/internal/entity"
	"github.com/KaiserWerk/CertMaker/internal/templateservice"
	"net/http"
)

func ProfileHandler(w http.ResponseWriter, r *http.Request) {
	var (
		val = r.Context().Value("user")
		u = val.(entity.User)
	)

	data := struct {
		User entity.User
	}{
		User: u,
	}

	if err := templateservice.ExecuteTemplate(w, "user/profile_edit.gohtml", data); err != nil {
		w.WriteHeader(http.StatusNotFound)
	}
}

func ProfileEditHandler(w http.ResponseWriter, r *http.Request) {
	var (
		val = r.Context().Value("user")
		u = val.(entity.User)
		message string
		changes uint8
	)

	if r.Method == http.MethodPost {
		ds := dbservice.New()
		form := r.FormValue("form_name")
		if form == "personal_data" {
			username := r.FormValue("username")
			if username != "" {
				_, err := ds.FindUser("username = ?", username)
				if err == nil {
					message += "Username is already in use!"
				} else {
					u.Username = username
					changes++
				}
			}

			email := r.FormValue("email")
			if email != "" {
				_, err := ds.FindUser("email = ?", email)
				if err == nil {
					message += "Email is already in use!"
				} else {
					u.Email = email
					changes++
				}
			}


		} else if form == "change_password" {

		}
		// check username
		// check email

		// or check passwords, depending on form
	}

	data := struct {
		User entity.User
		Message string
	}{
		User: u,
		Message: message,
	}

	if err := templateservice.ExecuteTemplate(w, "user/profile.gohtml", data); err != nil {
		w.WriteHeader(http.StatusNotFound)
	}
}

func ProfileRegenerateKeyHandler(w http.ResponseWriter, r *http.Request) {

}
