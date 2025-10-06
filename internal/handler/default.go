package handler

import (
	"net/http"

	"github.com/KaiserWerk/CertMaker/internal/assets"
	"github.com/KaiserWerk/CertMaker/internal/entity"
	"github.com/KaiserWerk/CertMaker/internal/templating"
)

// IndexHandler shows, well, the index page.
func (bh *BaseHandler) IndexHandler(w http.ResponseWriter, r *http.Request) {
	logger := bh.ContextLogger("index")
	const template = "index.html"

	certCount, err := bh.DBSvc.GetCertInfoCount()
	if err != nil {
		http.Error(w, "could not get cert count: "+err.Error(), http.StatusInternalServerError)
		return
	}
	byCSRCount, err := bh.DBSvc.GetCertInfoCountWhere("from_csr = ?", 1)
	if err != nil {
		http.Error(w, "could not get cert count: "+err.Error(), http.StatusInternalServerError)
		return
	}
	bySRCount, err := bh.DBSvc.GetCertInfoCountWhere("from_csr = ?", 0)
	if err != nil {
		http.Error(w, "could not get cert count: "+err.Error(), http.StatusInternalServerError)
		return
	}

	data := struct {
		Error      string
		Success    string
		Info       string
		User       *entity.User
		CertCount  int64
		ByCSRCount int64
		BySRCount  int64
	}{
		Error:      templating.GetErrorMessage(w, r),
		Success:    templating.GetSuccessMessage(w, r),
		Info:       templating.GetInfoMessage(w, r),
		CertCount:  certCount,
		ByCSRCount: byCSRCount,
		BySRCount:  bySRCount,
	}

	user, ok := r.Context().Value("user").(*entity.User)
	if !ok || user == nil {
		http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
		return
	}
	data.User = user

	if err := templating.ExecuteTemplate(w, template, data); err != nil {
		logger.Errorf("could not execute template %s: %v", template, err)
	}
}

// FaviconHandler returns just the favicon.
func (bh *BaseHandler) FaviconHandler(w http.ResponseWriter, r *http.Request) {
	icon, err := assets.GetStaticFS().ReadFile("static/favicon.ico")
	if err != nil {
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "image/x-icon")
	_, _ = w.Write(icon)
}
