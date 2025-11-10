package handler

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/KaiserWerk/CertMaker/internal/entity"
	"github.com/KaiserWerk/CertMaker/internal/global"
	"github.com/KaiserWerk/CertMaker/internal/security"
	"github.com/KaiserWerk/CertMaker/internal/templating"

	"github.com/gorilla/mux"
)

func (bh *BaseHandler) ListAPIKeysHandler(w http.ResponseWriter, r *http.Request) {
	var (
		template = "user_api_key_list.html"
		logger   = bh.ContextLogger("api_key")
	)
	defer r.Body.Close()

	user, ok := r.Context().Value("user").(*entity.User)
	if !ok || user == nil {
		http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
		return
	}

	data := struct {
		Error   string
		Success string
		Info    string
		User    *entity.User
		APIKeys []*entity.APIKey
	}{
		Error:   templating.GetErrorMessage(w, r),
		Success: templating.GetSuccessMessage(w, r),
		Info:    templating.GetInfoMessage(w, r),
		User:    user,
	}

	apiKeys, err := bh.DBSvc.GetAPIKeysForUser(user.ID)
	if err != nil {
		logger.Errorf("could not get API keys for user %d: %s", user.ID, err.Error())
		templating.SetErrorMessage(w, "Could not load API keys.")
		http.Redirect(w, r, "/user/profile", http.StatusSeeOther)
		return
	}
	data.APIKeys = apiKeys

	if err := templating.ExecuteTemplate(w, template, data); err != nil {
		logger.Errorf("could not execute template %s: %s", template, err.Error())
	}
}

// AddAPIKeyHandler generates a new API key for the current user and saves it to the DB
func (bh *BaseHandler) AddAPIKeyHandler(w http.ResponseWriter, r *http.Request) {
	var (
		template = "user_api_key_form.html"
		logger   = bh.ContextLogger("api_key")
	)
	defer r.Body.Close()

	user, ok := r.Context().Value("user").(*entity.User)
	if !ok || user == nil {
		http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
		return
	}

	data := struct {
		Error   string
		Success string
		Info    string
		Edit    bool
		User    *entity.User
		Issuers []*entity.Issuer
	}{
		Error:   templating.GetErrorMessage(w, r),
		Success: templating.GetSuccessMessage(w, r),
		Info:    templating.GetInfoMessage(w, r),
		User:    user,
	}

	issuers, err := bh.DBSvc.GetAllIssuers()
	if err != nil {
		logger.Errorf("could not get issuers: %s", err.Error())
		templating.SetErrorMessage(w, "Could not load issuers.")
		http.Redirect(w, r, "/user/apikey/list", http.StatusSeeOther)
		return
	}
	data.Issuers = issuers

	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			logger.Errorf("could not parse form: %s", err.Error())
			templating.SetErrorMessage(w, "Could not parse form.")
			http.Redirect(w, r, "/user/apikey/add", http.StatusSeeOther)
			return
		}

		allowedIssuers := r.Form["issuers"]
		if len(allowedIssuers) == 0 {
			templating.SetErrorMessage(w, "At least one issuer must be selected.")
			http.Redirect(w, r, "/user/apikey/add", http.StatusSeeOther)
			return
		}

		for _, issuerIDRaw := range allowedIssuers {
			issuerID, err := strconv.ParseUint(issuerIDRaw, 10, 64)
			if err != nil {
				logger.Debug("could not parse issuer ID: " + err.Error())
				templating.SetErrorMessage(w, "Invalid issuer ID.")
				http.Redirect(w, r, "/user/apikey/add", http.StatusSeeOther)
				return
			}

			if !bh.DBSvc.IssuerExists(issuerID) {
				logger.Debug("issuer does not exist: " + issuerIDRaw)
				templating.SetErrorMessage(w, "One of the selected issuers does not exist.")
				http.Redirect(w, r, "/user/apikey/add", http.StatusSeeOther)
				return
			}
		}

		newKey := &entity.APIKey{
			UserID:         user.ID,
			Key:            security.GenerateToken(global.APITokenLength, user.ID),
			Name:           r.FormValue("key_name"),
			AllowedIssuers: strings.Join(allowedIssuers, ","),
		}

		if err = bh.DBSvc.AddAPIKey(newKey); err != nil {
			logger.Errorf("could not add API key: %s", err.Error())
			templating.SetErrorMessage(w, "Could not create API key.")
			http.Redirect(w, r, "/user/apikey/add", http.StatusSeeOther)
			return
		}

		templating.SetSuccessMessage(w, "API key created successfully! Make sure to copy the key now, as it will not be shown again: "+newKey.Key)
		http.Redirect(w, r, "/user/apikey/list", http.StatusSeeOther)
	}

	if err := templating.ExecuteTemplate(w, template, data); err != nil {
		logger.Errorf("could not execute template %s: %s", template, err.Error())
	}
}

func (bh *BaseHandler) EditAPIKeyHandler(w http.ResponseWriter, r *http.Request) {
	var (
		template = "user_api_key_form.html"
		logger   = bh.ContextLogger("api_key")
	)
	defer r.Body.Close()

	user, ok := r.Context().Value("user").(*entity.User)
	if !ok || user == nil {
		http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
		return
	}

	data := struct {
		Error   string
		Success string
		Info    string
		Edit    bool
		User    *entity.User
	}{
		Error:   templating.GetErrorMessage(w, r),
		Success: templating.GetSuccessMessage(w, r),
		Info:    templating.GetInfoMessage(w, r),
		Edit:    true,
		User:    user,
	}
	if err := templating.ExecuteTemplate(w, template, data); err != nil {
		logger.Errorf("could not execute template %s: %s", template, err.Error())
	}
}

func (bh *BaseHandler) RemoveAPIKeyHandler(w http.ResponseWriter, r *http.Request) {
	var (
		logger = bh.ContextLogger("api_key")
		vars   = mux.Vars(r)
	)
	defer r.Body.Close()

	user, ok := r.Context().Value("user").(*entity.User)
	if !ok || user == nil {
		http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
		return
	}

	id := vars["id"]
	apiKeyID, err := strconv.ParseUint(id, 10, 64)
	if err != nil {
		logger.Debug("could not parse API key ID: " + err.Error())
		templating.SetErrorMessage(w, "Invalid API key ID.")
		http.Redirect(w, r, "/user/apikey/list", http.StatusSeeOther)
		return
	}

	apiKey, err := bh.DBSvc.FindAPIKeyForUser(user.ID, apiKeyID)
	if err != nil {
		logger.Errorf("could not find API key: %s", err.Error())
		templating.SetErrorMessage(w, "Could not find API key.")
		http.Redirect(w, r, "/user/apikey/list", http.StatusSeeOther)
		return
	}

	err = bh.DBSvc.DeleteAPIKey(apiKey)
	if err != nil {
		logger.Errorf("could not delete API key: %s", err.Error())
		templating.SetErrorMessage(w, "Could not delete API key.")
		http.Redirect(w, r, "/user/apikey/list", http.StatusSeeOther)
		return
	}

	templating.SetSuccessMessage(w, "API key deleted successfully.")
	http.Redirect(w, r, "/user/apikey/list", http.StatusSeeOther)
}
