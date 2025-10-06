package templating

import (
	"embed"
	"fmt"
	"html/template"
	"io"
)

//go:embed templates/*.html
var templateFS embed.FS

var templates *template.Template

func Start() error {
	var err error
	templates, err = template.New("").ParseFS(templateFS, "templates/*.html")
	if err != nil {
		return fmt.Errorf("error parsing the templates: %v", err)
	}

	// dir, err := templateFS.ReadDir("templates")
	// if err == nil {
	// 	// output each entry
	// 	for _, entry := range dir {
	// 		t := templates.Lookup(entry.Name())
	// 		if t != nil {
	// 			fmt.Println("Loaded template:", entry.Name())
	// 		} else {
	// 			fmt.Println("Failed to load template:", entry.Name())
	// 		}
	// 	}
	// }

	return nil
}

func ExecuteTemplate(w io.Writer, name string, data any) error {
	return templates.ExecuteTemplate(w, name, data)
}

// func ExecuteTemplate(inj *TplInjector, w io.Writer, file string, data any) error {
// 	logger := inj.Logger.WithField("context", "templates")
// 	var err error
// 	layoutContent, err := templateFS.ReadFile("templates/_layout.gohtml")
// 	if err != nil {
// 		logger.Error("could not get layout template: " + err.Error())
// 		return err
// 	}

// 	layout := template.Must(template.New("_layout.gohtml").Parse(string(layoutContent)))

// 	content, err := templateFS.ReadFile("templates/content/" + file)
// 	if err != nil {
// 		logger.Error("could not find template " + file + ": " + err.Error())
// 		return err
// 	}

// 	tmpl := template.Must(layout.Clone())
// 	_, err = tmpl.Parse(string(content))
// 	if err != nil {
// 		logger.Error("could not parse template into base layout: " + err.Error())
// 		return err
// 	}

// 	err = tmpl.Execute(w, data)
// 	if err != nil {
// 		logger.Error("could not execute template " + file + ": " + err.Error())
// 		return err
// 	}

// 	return nil
// }
