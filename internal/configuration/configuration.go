package configuration

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/KaiserWerk/CertMaker/internal/assets"
	"github.com/KaiserWerk/CertMaker/internal/helper"

	"gopkg.in/yaml.v2"
)

// AppConfig represents the Go type of a configuration file
type AppConfig struct {
	ServerHost string `yaml:"server_host"`
	DataDir    string `yaml:"data_dir"`
	Database   struct {
		Driver string `yaml:"driver"`
		DSN    string `yaml:"dsn"`
	} `yaml:"database"`
	RootKeyAlgo     string `yaml:"root_key_algo"`
	RootCertSubject struct {
		Organization  string `yaml:"organization"`
		Country       string `yaml:"country"`
		Province      string `yaml:"province"`
		Locality      string `yaml:"locality"`
		StreetAddress string `yaml:"street_address"`
		PostalCode    string `yaml:"postal_code"`
	} `yaml:"root_cert_subject"`
}

var (
	configDistFile = "config.dist.yaml"
	snDistFile     = "sn.dist.txt"
)

// Setup makes sure the configuration file and serial
// number file exist. If not, they are created with sensible defaults.
//
// Returns *AppConfig on success.
func Setup(file string) (*AppConfig, bool, error) {
	var created bool

	if !helper.DoesFileExist(file) {
		cont, err := assets.ReadConfigFile(configDistFile)
		if err != nil {
			return nil, false, fmt.Errorf("config dist file '%s' not readable in embed.FS: %s", configDistFile, err.Error())
		}

		targetFile, err := os.Create(file)
		if err != nil {
			return nil, false, fmt.Errorf("could not create config file '%s': %s", file, err.Error())
		}

		_, err = targetFile.Write(cont)
		if err != nil {
			return nil, false, fmt.Errorf("could not write dist file content to newly created config file '%s': %s", file, err.Error())
		}

		created = true
	}

	cont, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, created, err
	}

	var cfg AppConfig
	err = yaml.Unmarshal(cont, &cfg)
	if err != nil {
		return nil, created, err
	}

	snFile := filepath.Join(cfg.DataDir, "sn.txt")
	if !helper.DoesFileExist(snFile) {
		snCont, err := assets.ReadConfigFile(snDistFile)
		if err != nil {
			return nil, created, fmt.Errorf("serial number dist file '%s' not readable in embed.FS: %s", snDistFile, err.Error())
		}

		targetFile, err := os.Create(snFile)
		if err != nil {
			return nil, created, fmt.Errorf("could not create serial number file '%s': %s", snFile, err.Error())
		}

		_, err = targetFile.Write(snCont)
		if err != nil {
			return nil, created, fmt.Errorf("could not write dist file content to newly created serial number file '%s': %s", snFile, err.Error())
		}
	}

	return &cfg, created, nil
}
