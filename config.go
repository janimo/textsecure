// Copyright (c) 2014 Canonical Ltd.
// Licensed under the GPLv3, see the COPYING file for details.

package textsecure

import (
	"io/ioutil"
	"path/filepath"

	"gopkg.in/yaml.v2"
)

var (
	configDir  string
	configFile string
)

// Config holds application configuration settings
type Config struct {
	Tel                string `yaml:"tel"`                // Our telephone number
	Server             string `yaml:"server"`             // The TextSecure server URL
	SkipTLSCheck       bool   `yaml:"skipTLSCheck"`       // Allow self-signed TLS certificates for the server
	VerificationType   string `yaml:"verificationType"`   // Code verification method during registration (SMS/VOICE/DEV)
	StorageDir         string `yaml:"storageDir"`         // Directory for the persistent storage
	UnencryptedStorage bool   `yaml:"unencryptedStorage"` // Whether to store plaintext keys and session state (only for development)
	StoragePassword    string `yaml:"storagePassword"`    // Password to the storage
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

func loadConfig() (*Config, error) {
	if client.GetConfig != nil {
		return client.GetConfig()
	}

	configDir = filepath.Join(client.RootDir, ".config")
	configFile = filepath.Join(configDir, "config.yml")
	config, err := readConfig(configFile)
	if err != nil {
		return nil, err
	}
	return config, nil
}
