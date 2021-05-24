package assets

import (
	"embed"
)

//go:embed config/*
var configFS embed.FS

// GetConfigFS returns the filesystem containing
// configuration files
func GetConfigFS() *embed.FS {
	return &configFS
}

//go:embed static
var staticFS embed.FS

// GetStaticFS returns the filesystem containing
// static files to be served via HTTP
func GetStaticFS() embed.FS {
	return staticFS
}