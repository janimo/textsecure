// Copyright (c) 2014 Canonical Ltd.
// Licensed under the GPLv3, see the COPYING file for details.

package textsecure

import (
	"io/ioutil"

	"github.com/nanu-c/textsecure/protobuf"
	log "github.com/sirupsen/logrus"

	"gopkg.in/yaml.v2"
)

// Contact contains information about a contact.
type Contact struct {
	Tel         string
	Uuid        string
	Name        string
	Color       string
	Avatar      []byte
	Blocked     bool
	ExpireTimer uint32
}

type yamlContacts struct {
	Contacts []Contact
}

var (
	contactsFile string
	contacts     = map[string]Contact{}
)

// ReadContacts reads a YAML contacts file
func loadContacts(contactsYaml *yamlContacts) {
	for _, c := range contactsYaml.Contacts {
		contacts[c.Tel] = c
	}
}

var filePath string

func ReadContacts(fileName string) ([]Contact, error) {
	b, err := ioutil.ReadFile(fileName)
	filePath = fileName
	if err != nil {
		return nil, err
	}
	contactsYaml := &yamlContacts{}
	err = yaml.Unmarshal(b, contactsYaml)
	if err != nil {
		return nil, err
	}
	loadContacts(contactsYaml)
	return contactsYaml.Contacts, nil
}

// WriteContacts saves a list of contacts to a file
func WriteContacts(filename string, contacts2 []Contact) error {
	c := &yamlContacts{contacts2}
	// func WriteContacts(filename string) error {
	b, err := yaml.Marshal(c)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(filename, b, 0600)
}
func WriteContactsToPath() error {
	c := contactsToYaml()
	b, err := yaml.Marshal(c)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(filePath, b, 0600)
}
func contactsToYaml() *yamlContacts {
	c := &yamlContacts{}
	for _, co := range contacts {
		c.Contacts = append(c.Contacts, co)
	}
	return c
}

// type AvatarDetail struct {
// 	Length
// }

func updateContact(c *signalservice.ContactDetails) error {
	log.Debugln("[textsecure] updateContact ", c.GetName())

	// var r io.Reader
	// av := c.GetAvatar()
	// buf := new(bytes.Buffer)
	// if av != nil {
	// 	att, err := handleSingleAttachment(av)
	// 	if err != nil {
	// 		return err
	// 	}
	// 	r = att.R
	// 	buf.ReadFrom(r)
	// }

	contacts[c.GetNumber()] = Contact{
		Tel:         c.GetNumber(),
		Uuid:        c.GetUuid(),
		Name:        c.GetName(),
		Color:       c.GetColor(),
		Avatar:      []byte(""),
		Blocked:     c.GetBlocked(),
		ExpireTimer: c.GetExpireTimer(),
	}
	return WriteContactsToPath()
}
func handleContacts(src string, dm *signalservice.DataMessage) ([]*signalservice.DataMessage_Contact, error) {
	cs := dm.GetContact()
	if cs == nil {
		return nil, nil
	}

	for _, c := range cs {

		log.Debugln("[textsecure] handle Contact", c.GetName())
	}
	// switch c.GetType() {
	// case signalservice.GroupContext_UPDATE:
	// 	if err := updateGroup(gr); err != nil {
	// 		return nil, err
	// 	}
	// 	groups[hexid].Flags = GroupUpdateFlag
	// case signalservice.GroupContext_DELIVER:
	// 	if _, ok := groups[hexid]; !ok {
	// 		g, _ := newPartlyGroup(gr.GetId())
	// 		RequestGroupInfo(g)
	// 		setupGroups()
	// 		return nil, UnknownGroupIDError{hexid}
	// 	}
	// 	groups[hexid].Flags = 0
	// case signalservice.GroupContext_QUIT:
	// 	if err := quitGroup(src, hexid); err != nil {
	// 		return nil, err
	// 	}
	// 	groups[hexid].Flags = GroupLeaveFlag
	// }

	return nil, nil
}
func RequestContactInfo() error {
	var t signalservice.SyncMessage_Request_Type
	t = 1
	omsg := &signalservice.SyncMessage{
		Request: &signalservice.SyncMessage_Request{
			Type: &t,
		},
	}
	_, err := sendSyncMessage(omsg)
	if err != nil {
		return err
	}

	return nil
}
