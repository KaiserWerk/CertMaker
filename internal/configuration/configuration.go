package configuration

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/KaiserWerk/CertMaker/internal/assets"
	"github.com/KaiserWerk/CertMaker/internal/helper"
	"gopkg.in/yaml.v2"
)

type (
	// AppConfig represents the Go type of a configuration file
	AppConfig struct {
		App             App              `yaml:"app"`
		Database        DB               `yaml:"database"`
		RootKeyAlgo     string           `yaml:"root_key_algo"`
		RootCertSubject CertSubject      `yaml:"root_cert_subject"`
		StorageBox      StorageBoxConfig `yaml:"storagebox"`
	}
	App struct {
		BindAddress string `yaml:"bind_address"`
		ServerHost  string `yaml:"server_host"`
		DataDir     string `yaml:"data_dir"`
		LogDir      string `yaml:"log_dir"`
	}
	DB struct {
		Driver string `yaml:"driver"`
		DSN    string `yaml:"dsn"`
	}
	CertSubject struct {
		Organization  string `yaml:"organization"`
		Country       string `yaml:"country"`
		Province      string `yaml:"province"`
		Locality      string `yaml:"locality"`
		StreetAddress string `yaml:"street_address"`
		PostalCode    string `yaml:"postal_code"`
	}
	StorageBoxConfig struct {
		Username string `yaml:"username"`
		Password string `yaml:"password"`
		Host     string `yaml:"host"`
	}
)

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

	cont, err := os.ReadFile(file)
	if err != nil {
		return nil, created, err
	}

	var cfg AppConfig
	err = yaml.Unmarshal(cont, &cfg)
	if err != nil {
		return nil, created, err
	}
	if err := applyEnvOverrides(&cfg); err != nil {
		return nil, created, err
	}

	_ = os.MkdirAll(cfg.App.DataDir, os.ModePerm)
	snFile := filepath.Join(cfg.App.DataDir, "sn.txt")
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

func applyEnvOverrides(cfg *AppConfig) error {
	if driver, ok := lookupNonEmptyEnv("DB_DRIVER"); ok {
		cfg.Database.Driver = driver
	}

	if dsn, ok := lookupNonEmptyEnv("DB_DSN"); ok {
		cfg.Database.DSN = dsn
		return nil
	}

	mysqlEnvVars := []string{"DB_HOST", "DB_PORT", "DB_USER", "DB_PASSWORD", "DB_NAME"}
	mysqlEnvGiven := false
	for _, envVar := range mysqlEnvVars {
		if _, ok := lookupNonEmptyEnv(envVar); ok {
			mysqlEnvGiven = true
			break
		}
	}
	if !mysqlEnvGiven {
		return nil
	}

	host, hostGiven := lookupNonEmptyEnv("DB_HOST")
	user, userGiven := lookupNonEmptyEnv("DB_USER")
	password, passwordGiven := lookupNonEmptyEnv("DB_PASSWORD")
	dbName, dbNameGiven := lookupNonEmptyEnv("DB_NAME")

	missing := make([]string, 0, 4)
	if !hostGiven {
		missing = append(missing, "DB_HOST")
	}
	if !userGiven {
		missing = append(missing, "DB_USER")
	}
	if !passwordGiven {
		missing = append(missing, "DB_PASSWORD")
	}
	if !dbNameGiven {
		missing = append(missing, "DB_NAME")
	}
	if len(missing) > 0 {
		return fmt.Errorf("incomplete mysql environment override, missing: %s", strings.Join(missing, ", "))
	}

	port := "3306"
	if envPort, ok := lookupNonEmptyEnv("DB_PORT"); ok {
		port = envPort
	}

	params := "parseTime=true&charset=utf8"
	if envParams, ok := lookupNonEmptyEnv("DB_PARAMS"); ok {
		params = envParams
	}

	if cfg.Database.Driver == "" {
		cfg.Database.Driver = "mysql"
	}

	cfg.Database.DSN = fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?%s", user, password, host, port, dbName, params)
	return nil
}

func lookupNonEmptyEnv(key string) (string, bool) {
	value, found := os.LookupEnv(key)
	if !found {
		return "", false
	}

	trimmedValue := strings.TrimSpace(value)
	if trimmedValue == "" {
		return "", false
	}

	return trimmedValue, true
}
