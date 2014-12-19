// Copyright (c) 2014 Canonical Ltd.
// Licensed under the GPLv3, see the COPYING file for details.

package textsecure

import (
	"io/ioutil"

	"gopkg.in/yaml.v2"
)

type Config struct {
	Tel              string `yaml:"tel"`
	Server           string `yaml:"server"`
	SkipTLSCheck     bool   `yaml:"skipTLSCheck"`
	VerificationType string `yaml:"verificationType"`

	StoragePassword string `yaml:"storagePassword"`
}

// readConfig reads a YAML config file
func readConfig(fileName string) (*Config, error) {
	b, err := ioutil.ReadFile(fileName)
	if err != nil {
		return nil, err
	}

	cfg := &Config{}
	err = yaml.Unmarshal(b, cfg)
	if err != nil {
		return nil, err
	}
	return cfg, nil
}
