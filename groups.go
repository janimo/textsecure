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

	"github.com/aebruno/textsecure/protobuf"
	"gopkg.in/yaml.v2"
)

// Group holds group metadata.
type Group struct {
	ID      []byte
	Hexid   string
	Flags   uint32
	Name    string
	Members []string
	Avatar  io.Reader `yaml:"-"`
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
func updateGroup(gr *signalservice.GroupContext) error {
	hexid := idToHex(gr.GetId())

	var r io.Reader

	if av := gr.GetAvatar(); av != nil {
		att, err := handleSingleAttachment(av)
		if err != nil {
			return err
		}
		r = att.R
	}

	groups[hexid] = &Group{
		ID:      gr.GetId(),
		Hexid:   hexid,
		Name:    gr.GetName(),
		Members: gr.GetMembers(),
		Avatar:  r,
	}
	return saveGroup(hexid)
}

// UnknownGroupIDError is returned when an unknown group id is encountered
type UnknownGroupIDError struct {
	id string
}

func (err UnknownGroupIDError) Error() string {
	return fmt.Sprintf("unknown group ID %s", err.id)
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

// GroupUpdateFlag signals that this message updates the group membership or name.
var GroupUpdateFlag uint32 = 1

// GroupLeavelag signals that this message is a group leave message
var GroupLeaveFlag uint32 = 2

// handleGroups is the main entry point for handling the group metadata on messages.
func handleGroups(src string, dm *signalservice.DataMessage) (*Group, error) {
	gr := dm.GetGroup()
	if gr == nil {
		return nil, nil
	}
	hexid := idToHex(gr.GetId())

	switch gr.GetType() {
	case signalservice.GroupContext_UPDATE:
		if err := updateGroup(gr); err != nil {
			return nil, err
		}
		groups[hexid].Flags = GroupUpdateFlag
	case signalservice.GroupContext_DELIVER:
		if _, ok := groups[hexid]; !ok {
			return nil, UnknownGroupIDError{hexid}
		}
		groups[hexid].Flags = 0
	case signalservice.GroupContext_QUIT:
		if err := quitGroup(src, hexid); err != nil {
			return nil, err
		}
		groups[hexid].Flags = GroupLeaveFlag
	}

	return groups[hexid], nil
}

type groupMessage struct {
	id      []byte
	name    string
	members []string
	typ     signalservice.GroupContext_Type
}

func sendGroupHelper(hexid string, msg string, a *att) (uint64, error) {
	var ts uint64
	var err error
	g, ok := groups[hexid]
	if !ok {
		return 0, UnknownGroupIDError{hexid}
	}
	for _, m := range g.Members {
		if m != config.Tel {
			omsg := &outgoingMessage{
				tel:        m,
				msg:        msg,
				attachment: a,
				group: &groupMessage{
					id:  g.ID,
					typ: signalservice.GroupContext_DELIVER,
				},
			}
			ts, err = sendMessage(omsg)
			if err != nil {
				return 0, err
			}
		}
	}
	return ts, nil
}

// SendGroupMessage sends a text message to a given group.
func SendGroupMessage(hexid string, msg string) (uint64, error) {
	return sendGroupHelper(hexid, msg, nil)
}

// SendGroupAttachment sends an attachment to a given group.
func SendGroupAttachment(hexid string, msg string, r io.Reader) (uint64, error) {
	ct, r := MIMETypeFromReader(r)
	a, err := uploadAttachment(r, ct)
	if err != nil {
		return 0, err
	}
	return sendGroupHelper(hexid, msg, a)
}

func newGroupID() []byte {
	id := make([]byte, 16)
	randBytes(id)
	return id
}

func newGroup(name string, members []string) (*Group, error) {
	id := newGroupID()
	hexid := idToHex(id)
	groups[hexid] = &Group{
		ID:      id,
		Hexid:   hexid,
		Name:    name,
		Members: append(members, config.Tel),
	}
	err := saveGroup(hexid)
	if err != nil {
		return nil, err
	}
	return groups[hexid], nil
}

func changeGroup(hexid, name string, members []string) (*Group, error) {
	g, ok := groups[hexid]
	if !ok {
		return nil, UnknownGroupIDError{hexid}
	}

	g.Name = name
	g.Members = append(members, config.Tel)
	saveGroup(hexid)

	return g, nil
}

func sendUpdate(g *Group) error {
	for _, m := range g.Members {
		if m != config.Tel {
			omsg := &outgoingMessage{
				tel: m,
				group: &groupMessage{
					id:      g.ID,
					name:    g.Name,
					members: g.Members,
					typ:     signalservice.GroupContext_UPDATE,
				},
			}
			_, err := sendMessage(omsg)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// NewGroup creates a group and notifies its members.
// Our phone number is automatically added to members.
func NewGroup(name string, members []string) (*Group, error) {
	g, err := newGroup(name, members)
	if err != nil {
		return nil, err
	}
	return g, sendUpdate(g)
}

// UpdateGroup updates the group name and/or membership.
// Our phone number is automatically added to members.
func UpdateGroup(hexid, name string, members []string) (*Group, error) {
	g, err := changeGroup(hexid, name, members)
	if err != nil {
		return nil, err
	}
	return g, sendUpdate(g)
}

func removeGroup(id []byte) error {
	hexid := idToHex(id)
	err := os.Remove(idToPath(hexid))
	if err != nil {
		return err
	}
	return nil
}

// LeaveGroup sends a group quit message to the other members of the given group.
func LeaveGroup(hexid string) error {
	g, ok := groups[hexid]
	if !ok {
		return UnknownGroupIDError{hexid}
	}

	for _, m := range g.Members {
		if m != config.Tel {
			omsg := &outgoingMessage{
				tel: m,
				group: &groupMessage{
					id:  g.ID,
					typ: signalservice.GroupContext_QUIT,
				},
			}
			_, err := sendMessage(omsg)
			if err != nil {
				return err
			}
		}
	}
	removeGroup(g.ID)
	return nil
}
