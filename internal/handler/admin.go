package handler

import (
	"fmt"
	"github.com/KaiserWerk/CertMaker/internal/dbservice"
	"github.com/KaiserWerk/CertMaker/internal/entity"
	"github.com/KaiserWerk/CertMaker/internal/logging"
	"github.com/KaiserWerk/CertMaker/internal/security"
	"github.com/KaiserWerk/CertMaker/internal/templateservice"
	"net/http"
)

func AdminSettingsHandler(w http.ResponseWriter, r *http.Request) {
	var (
		err error
		logger = logging.GetLogger()
		ds = dbservice.New()
	)

	if r.Method == http.MethodPost {

		var errors uint8 = 0
		form := r.FormValue("form")

		if form == "authentication" {
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
		w.WriteHeader(404)
	}
}

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
		w.WriteHeader(404)
	}
}

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

		if username == "" || email == "" || password == "" || password2 == "" {
			logger.Println("All fields required")
			http.Redirect(w, r, "/admin/user/add", http.StatusSeeOther)
			return
		}

		if password != password2 {
			logger.Println("passwords dont match")
			http.Redirect(w, r, "/admin/user/add", http.StatusSeeOther)
			return
		}

		// TODO check if username or email already in use
		ds := dbservice.New()
		_, err = ds.FindUser("username = ?", username)
		if err == nil {
			logger.Println("username already taken")
			http.Redirect(w, r, "/admin/user/add", http.StatusSeeOther)
			return
		}

		_, err = ds.FindUser("email = ?", email)
		if err == nil {
			logger.Println("email already taken")
			http.Redirect(w, r, "/admin/user/add", http.StatusSeeOther)
			return
		}


		apikey, err := security.GenerateToken(20)
		if err != nil {
			logger.Println("could not generate token: " + err.Error())
			http.Redirect(w, r, "/admin/user/add", http.StatusSeeOther)
			return
		}

		u := entity.User{
			Username: username,
			Email:    email,
			Password: password,
			ApiKey: string(apikey),
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
		w.WriteHeader(404)
	}
}

func AdminUserEditHandler(w http.ResponseWriter, r *http.Request) {



	if err := templateservice.ExecuteTemplate(w, "admin/user_edit.gohtml", nil); err != nil {
		w.WriteHeader(404)
	}
}

func AdminUserRemoveHandler(w http.ResponseWriter, r *http.Request) {

}