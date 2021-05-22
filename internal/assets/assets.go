package assets

import (
	"embed"
)

//go:embed config/*
var configFS embed.FS

func GetConfigFS() *embed.FS {
	return &configFS
}

//go:embed static
var staticFS embed.FS

func GetStaticFS() embed.FS {
	return staticFS
}