package templateservice

import (
	"embed"
	"github.com/KaiserWerk/CertMaker/internal/logging"
	"html/template"
	"io"
)

//go:embed templates/*
var templateFS embed.FS

func ExecuteTemplate(w io.Writer, file string, data interface{}) error {
	logger := logging.GetLogger().WithField("function", "templateservice.ExecuteTemplate")
	var err error
	layoutContent, err := templateFS.ReadFile("templates/_layout.gohtml")
	if err != nil {
		logger.Error("could not get layout template: " + err.Error())
		return err
	}

	layout := template.Must(template.New("_layout.gohtml").Parse(string(layoutContent)))

	content, err := templateFS.ReadFile("templates/content/" + file)
	if err != nil {
		logger.Error("could not find template " + file + ": " + err.Error())
		return err
	}

	tmpl := template.Must(layout.Clone())
	_, err = tmpl.Parse(string(content))
	if err != nil {
		logger.Error("could not parse template into base layout: " + err.Error())
		return err
	}

	err = tmpl.Execute(w, data)
	if err != nil {
		logger.Error("could not execute template " + file + ": " + err.Error())
		return err
	}

	return nil
}
