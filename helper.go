package main

import (
	"fmt"
	"gopkg.in/yaml.v2"
	"html/template"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

func trimSliceElements(parts []string) {
	for k, v := range parts {
		parts[k] = strings.TrimSpace(v)
	}
}

func visit(files *[]string) filepath.WalkFunc {
	return func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !strings.Contains(path, "-key.pem") {
			return err
		}

		*files = append(*files, path)
		return nil
	}
}

func doesFileExist(f string) bool {
	info, err := os.Stat(f)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

func getConfig() (*sysConf, error) {
	file := "config/config.yaml"
	if !doesFileExist(file) {
		return nil, fmt.Errorf("config file '%s' not found", file)
	}

	content, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, err
	}

	var s *sysConf
	err = yaml.Unmarshal(content, &s)
	if err != nil {
		return nil, err
	}

	return s, nil
}

func ExecuteTemplate(w http.ResponseWriter, file string, data interface{}) error {
	//var funcMap = template.FuncMap{
	//	"getBuildDefCaption": GetBuildDefCaption,
	//	"getUsernameById":    GetUsernameById,
	//	"getFlashbag":        GetFlashbag(GetSessionManager()),
	//	"formatDate":	      FormatDate,
	//}
	layoutContent, err := FSString(true, "/templates/_layout.gohtml") // with leading slash?
	if err != nil {
		fmt.Println("could not get layout template: " + err.Error())
		return err
	}

	layout := template.Must(template.New("_layout.gohtml").Parse(layoutContent)) //.Funcs(funcMap)

	content, err := FSString(true, "/templates/content/"+file) // with leading slash?
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
