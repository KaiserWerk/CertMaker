package handler

import (
	"github.com/KaiserWerk/CertMaker/internal/assets"
	"github.com/KaiserWerk/CertMaker/internal/templateservice"
	"net/http"
)

// IndexHandler shows, well, the index page
func IndexHandler(w http.ResponseWriter, r *http.Request) {
	//val := r.Context().Value("user")
	//u := val.(entity.User)
	//fmt.Println("Username: " + u.Username)

	if err := templateservice.ExecuteTemplate(w, "index.gohtml", nil); err != nil {
		w.WriteHeader(http.StatusNotFound)
	}
}

// FaviconHandler returns just the favicon
func FaviconHandler(w http.ResponseWriter, r *http.Request) {
	icon, err := assets.GetStaticFS().ReadFile("static/favicon.ico")
	if err != nil {
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "image/x-icon")
	_, _ = w.Write(icon)
}

