package templateservice

import (
	"embed"
	"fmt"
	"html/template"
	"io"
)

//go:embed templates/*
var templateFS embed.FS

func ExecuteTemplate(w io.Writer, file string, data interface{}) error {
	var err error
	//var funcMap = template.FuncMap{
	//	"getBuildDefCaption": GetBuildDefCaption,
	//	"getUsernameById":    GetUsernameById,
	//	"getFlashbag":        GetFlashbag(GetSessionManager()),
	//	"formatDate":	      FormatDate,
	//}
	layoutContent, err := templateFS.ReadFile("templates/_layout.gohtml") // with leading slash?
	if err != nil {
		fmt.Println("could not get layout template: " + err.Error())
		return err
	}

	layout := template.Must(template.New("_layout.gohtml").Parse(string(layoutContent))) //.Funcs(funcMap)

	content, err := templateFS.ReadFile("templates/content/" + file) // with leading slash?
	if err != nil {
		fmt.Println("could not find template " + file + ": " + err.Error())
		return err
	}

	tmpl := template.Must(layout.Clone())
	_, err = tmpl.Parse(string(content))
	if err != nil {
		fmt.Println("could not parse template into base layout: " + err.Error())
		return err
	}

	err = tmpl.Execute(w, data)
	if err != nil {
		fmt.Println("could not execute template " + file + ": " + err.Error())
		return err
	}

	return nil
}
