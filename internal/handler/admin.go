package handler

import (
	"fmt"
	"github.com/KaiserWerk/CertMaker/internal/logging"
	"github.com/KaiserWerk/CertMaker/internal/settings"
	"github.com/KaiserWerk/CertMaker/internal/templateservice"
	"net/http"
)

func AdminSettingsHandler(w http.ResponseWriter, r *http.Request) {
	var (
		err error
		logger = logging.GetLogger()
	)

	if r.Method == http.MethodPost {

		var errors uint8 = 0
		form := r.FormValue("form")

		if form == "authentication" {
			authprovUserpw := "0"
			if r.FormValue("authprovider_userpw") == "1" {
				authprovUserpw = "1"
			}
			err = settings.Set("authprovider_userpw", authprovUserpw)
			if err != nil {
				errors++
				logger.Println(err.Error())
			}

			authprovBearer := "0"
			if r.FormValue("authprovider_bearer") == "1" {
				authprovBearer = "1"
			}
			err = settings.Set("authprovider_bearer", authprovBearer)
			if err != nil {
				errors++
				logger.Println(err.Error())
			}

		} else if form == "certificates_and_requests" {

		}

		if errors > 0 {
			output := fmt.Sprintf("When trying to save admin settings, %d error(s) occurred", errors)
			logger.Println(output)
		} else {

		}

		http.Redirect(w, r, "/admin/settings", http.StatusSeeOther)
		return
	}


	if err := templateservice.ExecuteTemplate(w, "admin/settings.gohtml", nil); err != nil {
		w.WriteHeader(404)
	}
}
