package handler

import (
	"github.com/KaiserWerk/CertMaker/internal/assets"
	"github.com/KaiserWerk/CertMaker/internal/templates"
	"net/http"
)

// IndexHandler shows, well, the index page.
func (bh *BaseHandler) IndexHandler(w http.ResponseWriter, r *http.Request) {
	if err := templates.ExecuteTemplate(bh.Inj(), w, "index.gohtml", nil); err != nil {
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
