package main

import (
	"fmt"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"os"
)

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