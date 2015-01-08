// Copyright (c) 2014 Canonical Ltd.
// Licensed under the GPLv3, see the COPYING file for details.

package textsecure

import (
	"io/ioutil"
	"path/filepath"

	"gopkg.in/yaml.v2"
)

// Contact contains information about a contact.
type Contact struct {
	Name string
	Tel  string
}

type yamlContacts struct {
	Contacts []Contact
}

// readContacts reads a YAML contacts file
func readContacts(fileName string) ([]Contact, error) {
	b, err := ioutil.ReadFile(fileName)
	if err != nil {
		return nil, err
	}

	contacts := &yamlContacts{}
	err = yaml.Unmarshal(b, contacts)
	if err != nil {
		return nil, err
	}
	return contacts.Contacts, nil
}

func loadLocalContacts() ([]Contact, error) {
	var contacts []Contact
	var err error
	if client.GetLocalContacts != nil {
		contacts, err = client.GetLocalContacts()
		if err != nil {
			return nil, err
		}
	} else {
		contacts, err = readContacts(filepath.Join(configDir, "contacts.yml"))
		if err != nil {
			return nil, err
		}
	}
	return contacts, nil
}
