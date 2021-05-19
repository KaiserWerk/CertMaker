package global

import (
	"embed"
	"github.com/KaiserWerk/CertMaker/internal/assets"
	"github.com/KaiserWerk/CertMaker/internal/entity"
)

var config *entity.Configuration

func SetConfiguration(c *entity.Configuration) {
	config = c
}

func GetConfiguration() *entity.Configuration {
	return config
}

func GetAssets() *embed.FS {
	return &assets.AssetFS
}