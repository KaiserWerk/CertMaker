package handler

import (
	"github.com/KaiserWerk/CertMaker/internal/assets"
	"github.com/KaiserWerk/CertMaker/internal/templates"
	"net/http"
)

// IndexHandler shows, well, the index page.
func (bh *BaseHandler) IndexHandler(w http.ResponseWriter, r *http.Request) {
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
		CertCount  int64
		ByCSRCount int64
		BySRCount  int64
	}{
		CertCount:  certCount,
		ByCSRCount: byCSRCount,
		BySRCount:  bySRCount,
	}

	if err := templates.ExecuteTemplate(bh.Inj(), w, "index.gohtml", data); err != nil {
		w.WriteHeader(http.StatusNotFound)
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
