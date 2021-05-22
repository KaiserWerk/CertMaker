package entity

type Configuration struct {
	ServerHost string `yaml:"server_host"`
	DataDir    string `yaml:"data_dir"`
	Database struct {
		Driver string `yaml:"driver"`
		DSN string `yaml:"dsn"`
	} `yaml:"database"`
}
