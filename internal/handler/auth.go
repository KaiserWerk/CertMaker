package handler

import (
	"fmt"
	"github.com/KaiserWerk/CertMaker/internal/templateservice"
	"net/http"
)

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	if err := templateservice.ExecuteTemplate(w, "auth/login.gohtml", nil); err != nil {
		w.WriteHeader(404)
	}
}

func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, "logout")
}

func RegistrationHandler(w http.ResponseWriter, r *http.Request) {
	if err := templateservice.ExecuteTemplate(w, "auth/registration.gohtml", nil); err != nil {
		w.WriteHeader(404)
	}
}
