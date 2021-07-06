package templates

import (
	"embed"
	"fmt"
	"github.com/KaiserWerk/CertMaker/internal/logging"
	"html/template"
	"io"
	"net/http"
	"strings"
)

type MessageType string

const (
	typeHeader    = "X-GetMessage-Type"
	messageHeader = "X-GetMessage-Content"

	MsgSuccess MessageType = "success"
	MsgError   MessageType = "error"
	MsgWarning MessageType = "warning"
	MsgInfo    MessageType = "info"
)

//go:embed templates/*
var templateFS embed.FS

func ExecuteTemplate(w io.Writer, file string, data interface{}) error {
	var funcMap = template.FuncMap{
		//"getFlashbag":        GetFlashbag,
	}
	logger := logging.GetLogger().WithField("function", "templateservice.ExecuteTemplate")
	var err error
	layoutContent, err := templateFS.ReadFile("templates/_layout.gohtml")
	if err != nil {
		logger.Error("could not get layout template: " + err.Error())
		return err
	}

	layout := template.Must(template.New("_layout.gohtml").Parse(string(layoutContent))).Funcs(funcMap)

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

func SetMessage(r *http.Request, at MessageType, am string) {
	r.Header.Set(typeHeader, string(at))
	r.Header.Set(messageHeader, am)
	//r.Header[typeHeader] = []string{string(at)}
	//r.Header[messageHeader] = []string{am}
}

func GetMessage(r *http.Request, at MessageType, am string) template.HTML {
	var (
		msgType MessageType
		message string
		source string
	)

	tp := MessageType(r.Header.Get(typeHeader))
	msg := r.Header.Get(messageHeader)
	fmt.Println("Header: ", tp, msg)

	msgType = at
	message = am

	if at == "" || am == "" {
		msgType = tp
		message = msg
	}

	if tp == "" || msg == "" {
		return template.HTML("")
	}

	const msgSuccess = `<div class="alert alert-success alert-dismissable"><a href="#" class="close" data-dismiss="alert" aria-label="close">&times;</a><strong>Success!</strong> %%message%%</div>`
	const msgError = `<div class="alert alert-danger alert-dismissable"><a href="#" class="close" data-dismiss="alert" aria-label="close">&times;</a><strong>Error!</strong> %%message%%</div>`
	const msgWarning = `<div class="alert alert-warning alert-dismissable"><a href="#" class="close" data-dismiss="alert" aria-label="close">&times;</a><strong>Warning!</strong> %%message%%</div>`
	const msgInfo = `<div class="alert alert-info alert-dismissable"><a href="#" class="close" data-dismiss="alert" aria-label="close">&times;</a><strong>Info!</strong> %%message%%</div>`

	switch msgType {
	case MsgSuccess:
		source = msgSuccess
	case MsgError:
		source = msgError
	case MsgWarning:
		source = msgWarning
	case MsgInfo:
		source = msgInfo
	default:
		return template.HTML("")
	}

	source = strings.Replace(source, "%%message%%", message, 1)

	return template.HTML(source)
}
