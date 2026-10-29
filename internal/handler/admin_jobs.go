package handler

import (
	"net/http"

	"github.com/KaiserWerk/CertMaker/internal/entity"
	"github.com/KaiserWerk/CertMaker/internal/templating"
)

func (bh *BaseHandler) AdminJobListHandler(w http.ResponseWriter, r *http.Request) {
	var (
		template = "admin_job_list.html"
		logger   = bh.ContextLogger("admin")
	)

	data := struct {
		Error   string
		Success string
		Info    string
		User    *entity.User
		Jobs    []entity.JobInfo
	}{
		Error:   templating.GetErrorMessage(w, r),
		Success: templating.GetSuccessMessage(w, r),
		Info:    templating.GetInfoMessage(w, r),
	}

	user, ok := r.Context().Value("user").(*entity.User)
	if !ok || user == nil {
		http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
		return
	}
	data.User = user

	data.Jobs = bh.CronSvc.GetAllJobInfo()

	if err := templating.ExecuteTemplate(w, template, data); err != nil {
		logger.Errorf("could not execute template '%s': %s", template, err.Error())
	}
}
