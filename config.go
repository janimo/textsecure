// Copyright (c) 2014 Canonical Ltd.
// Licensed under the GPLv3, see the COPYING file for details.

package textsecure

import (
	"errors"
	"io/ioutil"

	"gopkg.in/yaml.v2"
)

// Config holds application configuration settings
type Config struct {
	Tel                string `yaml:"tel"`                // Our telephone number
	Server             string `yaml:"server"`             // The TextSecure server URL
	ProxyServer        string `yaml:"proxy"`              // HTTP Proxy URL if one is being used
	SkipTLSCheck       bool   `yaml:"skipTLSCheck"`       // Allow self-signed TLS certificates for the server
	VerificationType   string `yaml:"verificationType"`   // Code verification method during registration (SMS/VOICE/DEV)
	StorageDir         string `yaml:"storageDir"`         // Directory for the persistent storage
	UnencryptedStorage bool   `yaml:"unencryptedStorage"` // Whether to store plaintext keys and session state (only for development)
	StoragePassword    string `yaml:"storagePassword"`    // Password to the storage
}

// ReadConfig reads a YAML config file
func ReadConfig(fileName string) (*Config, error) {
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
	return nil, errors.New("Provide Client.GetConfig")
}
