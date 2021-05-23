package handler

import (
	"github.com/KaiserWerk/CertMaker/internal/templateservice"
	"net/http"
)

func IndexHandler(w http.ResponseWriter, r *http.Request) {
	//val := r.Context().Value("user")
	//u := val.(entity.User)
	//fmt.Println("Username: " + u.Username)

	if err := templateservice.ExecuteTemplate(w, "index.gohtml", nil); err != nil {
		w.WriteHeader(404)
	}
}



