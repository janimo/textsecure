// Copyright (c) 2014 Canonical Ltd.
// Licensed under the GPLv3, see the COPYING file for details.

package textsecure

import (
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/janimo/textsecure/protobuf"
	"github.com/janimo/textsecure/vendor/magic"
	"gopkg.in/yaml.v2"
)

// Group holds group metadata.
type Group struct {
	ID      []byte
	Name    string
	Members []string
}

var (
	groupDir string
	groups   = map[string]*Group{}
)

// idToHex returns the hex representation of the group id byte-slice
// to be used as both keys in the map and for naming the files.
func idToHex(id []byte) string {
	return hex.EncodeToString(id)
}

// idToPath returns the path of the file for storing a group's state
func idToPath(hexid string) string {
	return filepath.Join(groupDir, hexid)
}

// groupByName returns the group structure for the group with the given name
func groupByName(name string) *Group {
	for _, g := range groups {
		if name == g.Name {
			return g
		}
	}
	return nil
}

// FIXME: for now using unencrypted YAML files for group state,
// should be definitely encrypted and maybe another format.

// saveGroup stores a group's state in a file.
func saveGroup(hexid string) error {
	b, err := yaml.Marshal(groups[hexid])
	if err != nil {
		return err
	}
	return ioutil.WriteFile(idToPath(hexid), b, 0600)
}

// loadGroup loads a group's state from a file.
func loadGroup(path string) error {
	_, hexid := filepath.Split(path)
	b, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}

	group := &Group{}
	err = yaml.Unmarshal(b, group)
	if err != nil {
		return err
	}
	groups[hexid] = group
	return nil
}

// setupGroups reads all groups' state from storage.
func setupGroups() error {
	groupDir = filepath.Join(config.StorageDir, "groups")
	if err := os.MkdirAll(groupDir, 0700); err != nil {
		return err
	}
	filepath.Walk(groupDir, func(path string, fi os.FileInfo, err error) error {
		if !fi.IsDir() {
			if !strings.Contains(path, "avatar") {
				loadGroup(path)
			}
		}
		return nil

	})
	return nil
}

// avatarPath returns the path to the avatar image of a given group.
func avatarPath(hexid string) string {
	return idToPath(hexid) + "_avatar.png"
}

// removeMember removes a given number from a list.
func removeMember(tel string, members []string) []string {
	for i, m := range members {
		if m == tel {
			members = append(members[:i], members[i+1:]...)
			break
		}
	}
	return members
}

// updateGroup updates a group's state based on an incoming message.
func updateGroup(gr *textsecure.GroupContext) error {
	hexid := idToHex(gr.GetId())

	if av := gr.GetAvatar(); av != nil {
		avatarContents, err := handleSingleAttachment(av)
		if err != nil {
			return err
		}
		f, err := os.OpenFile(avatarPath(hexid), os.O_WRONLY, 0600)
		if err != nil {
			return err
		}
		_, err = io.Copy(f, avatarContents)
		if err != nil {
			return err
		}
	}

	groups[hexid] = &Group{
		ID:      gr.GetId(),
		Name:    gr.GetName(),
		Members: gr.GetMembers(),
	}
	return saveGroup(hexid)
}

// UnknownGroupIDError is returned when an unknown group id is encountered
type UnknownGroupIDError struct {
	id string
}

func (err UnknownGroupIDError) Error() string {
	return fmt.Sprintf("Unknown group ID %s", err.id)
}

// quitGroup removes a quitting member from the local group state.
func quitGroup(src string, hexid string) error {
	gr, ok := groups[hexid]
	if !ok {
		return UnknownGroupIDError{hexid}
	}

	gr.Members = removeMember(src, gr.Members)

	return saveGroup(hexid)
}

// handleGroups is the main entry point for handling the group metadata on messages.
func handleGroups(src string, dm *textsecure.DataMessage) (string, error) {
	gr := dm.GetGroup()
	if gr == nil {
		return "", nil
	}
	hexid := idToHex(gr.GetId())

	switch gr.GetType() {
	case textsecure.GroupContext_UPDATE:
		if err := updateGroup(gr); err != nil {
			return "", err
		}
	case textsecure.GroupContext_DELIVER:
		if g, ok := groups[hexid]; ok {
			return g.Name, nil
		}
		return "", UnknownGroupIDError{hexid}
	case textsecure.GroupContext_QUIT:
		if err := quitGroup(src, hexid); err != nil {
			return "", err
		}
	}

	return "", nil
}

type groupMessage struct {
	id      []byte
	name    string
	members []string
	typ     textsecure.GroupContext_Type
}

// UnknownGroupNameError is returned when an unknown group name is
type UnknownGroupNameError struct {
	name string
}

func (err UnknownGroupNameError) Error() string {
	return fmt.Sprintf("Unknown group name %s", err.name)
}

// SendGroupMessage sends a text message to a given group.
func SendGroupMessage(name string, msg string) error {
	g := groupByName(name)
	if g == nil {
		return UnknownGroupNameError{name}
	}
	for _, m := range g.Members {
		if m != config.Tel {
			omsg := &outgoingMessage{
				tel: m,
				msg: msg,
				group: &groupMessage{
					id:  g.ID,
					typ: textsecure.GroupContext_DELIVER,
				},
			}
			err, _ := sendMessage(omsg)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// SendGroupAttachment sends an attachment to a given group.
func SendGroupAttachment(name string, msg string, r io.Reader) error {
	ct, r := magic.MIMETypeFromReader(r)
	a, err := uploadAttachment(r, ct)
	if err != nil {
		return err
	}
	g := groupByName(name)
	if g == nil {
		return UnknownGroupNameError{name}
	}
	for _, m := range g.Members {
		if m != config.Tel {
			omsg := &outgoingMessage{
				tel:        m,
				msg:        msg,
				attachment: a,
				group: &groupMessage{
					id:  g.ID,
					typ: textsecure.GroupContext_DELIVER,
				},
			}
			err, _ := sendMessage(omsg)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func newGroupID() []byte {
	id := make([]byte, 10)
	randBytes(id)
	return id
}

func newGroup(name string, members []string) *Group {
	id := newGroupID()
	hexid := idToHex(id)
	groups[hexid] = &Group{
		ID:      id,
		Name:    name,
		Members: append(members, config.Tel),
	}
	saveGroup(hexid)
	return groups[hexid]
}

// GroupExistsError is returned when an attempt is made to create a group
// named like an already existing one.
type GroupExistsError struct {
	name string
}

func (err GroupExistsError) Error() string {
	return fmt.Sprintf("Group %s already exists", err.name)
}

// NewGroup creates a group and notifies its members.
// Our phone number is automatically added to members.
func NewGroup(name string, members []string) error {
	g := groupByName(name)
	if g != nil {
		return GroupExistsError{name}
	}

	g = newGroup(name, members)

	for _, m := range g.Members {
		if m != config.Tel {
			omsg := &outgoingMessage{
				tel: m,
				group: &groupMessage{
					id:      g.ID,
					name:    name,
					members: g.Members,
					typ:     textsecure.GroupContext_UPDATE,
				},
			}
			err, _ := sendMessage(omsg)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func removeGroup(id []byte) error {
	hexid := idToHex(id)
	err := os.Remove(idToPath(hexid))
	if err != nil {
		return err
	}
	os.Remove(avatarPath(hexid))
	return nil
}

// LeaveGroup sends a group quit message to the other members of the given group.
func LeaveGroup(name string) error {
	g := groupByName(name)
	if g == nil {
		return UnknownGroupNameError{name}
	}

	for _, m := range g.Members {
		if m != config.Tel {
			omsg := &outgoingMessage{
				tel: m,
				group: &groupMessage{
					id:  g.ID,
					typ: textsecure.GroupContext_QUIT,
				},
			}
			err, _ := sendMessage(omsg)
			if err != nil {
				return err
			}
		}
	}
	removeGroup(g.ID)
	return nil
}
