package templates

import (
	"embed"
	"html/template"
	"io"

	"github.com/sirupsen/logrus"
)

//go:embed templates/*
var templateFS embed.FS

type TplInjector struct {
	Logger *logrus.Entry
}

func ExecuteTemplate(inj *TplInjector, w io.Writer, file string, data any) error {
	logger := inj.Logger.WithField("context", "templates")
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
