package configuration

import (
	"fmt"
	"github.com/KaiserWerk/CertMaker/internal/assets"
	"github.com/KaiserWerk/CertMaker/internal/entity"
	"github.com/KaiserWerk/CertMaker/internal/global"
	"github.com/KaiserWerk/CertMaker/internal/helper"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"os"
	"path/filepath"
)

var (
	configurationFile = "config.yaml"
	configDistFile    = "config/config.dist.yaml"
	snFile = ""
	snDistFile = "config/sn.dist.txt"
)

func GetConfigFilename() string {
	return configurationFile
}

func GetSnFilename() string {
	return snFile
}

func SetFileSource(f string) {
	configurationFile = f
}

func Setup() (bool, bool, error) {
	var (
		createdConfigFile = false
		createdSnFile = false
		assets = assets.GetConfigFS()
	)

	if !helper.DoesFileExist(configurationFile) {
		cont, err := assets.ReadFile(configDistFile)
		if err != nil {
			return createdConfigFile, createdSnFile, fmt.Errorf("config dist file '%s' not readable in embed.FS: %s", configDistFile, err.Error())
		}

		targetFile, err := os.Create(configurationFile)
		if err != nil {
			return createdConfigFile, createdSnFile, fmt.Errorf("could not create config file '%s': %s", configurationFile, err.Error())
		}
		createdConfigFile = true

		_, err = targetFile.Write(cont)
		if err != nil {
			return createdConfigFile, createdSnFile, fmt.Errorf("could not write dist file content to newly created config file '%s': %s", configurationFile, err.Error())
		}
	}

	c, err := Get()
	if err != nil {
		return createdConfigFile, createdSnFile, fmt.Errorf("config from file '%s' is not parseable: %s", configurationFile, err.Error())
	}

	snFile = filepath.Join(c.DataDir, "sn.txt")
	if !helper.DoesFileExist(snFile) {
		snCont, err := assets.ReadFile("config/sn.dist.txt")
		if err != nil {
			return createdConfigFile, createdSnFile, fmt.Errorf("serial number dist file '%s' not readable in embed.FS: %s", snDistFile, err.Error())
		}

		targetFile, err := os.Create(snFile)
		if err != nil {
			return createdConfigFile, createdSnFile, fmt.Errorf("could not create serial number file '%s': %s", snFile, err.Error())
		}
		createdSnFile = true

		_, err = targetFile.Write(snCont)
		if err != nil {
			return createdConfigFile, createdSnFile, fmt.Errorf("could not write dist file content to newly created serial number file '%s': %s", snFile, err.Error())
		}
	}

	global.SetConfiguration(c)

	return createdConfigFile, createdSnFile, nil
}

func Get() (*entity.Configuration, error) {
	if !helper.DoesFileExist(configurationFile) {
		return nil, fmt.Errorf("config file '%s' not found", configurationFile)
	}

	content, err := ioutil.ReadFile(configurationFile)
	if err != nil {
		return nil, err
	}

	var s *entity.Configuration
	err = yaml.Unmarshal(content, &s)
	if err != nil {
		return nil, err
	}

	return s, nil
}
