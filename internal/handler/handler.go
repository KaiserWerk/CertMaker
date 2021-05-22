package handler

import (
	"github.com/KaiserWerk/CertMaker/internal/templateservice"
	"net/http"
)

func IndexHandler(w http.ResponseWriter, r *http.Request) {
	if err := templateservice.ExecuteTemplate(w, "index.gohtml", nil); err != nil {
		w.WriteHeader(404)
	}
}



