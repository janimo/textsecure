// Copyright (c) 2014 Canonical Ltd.
// Licensed under the GPLv3, see the COPYING file for details.

package textsecure

import (
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/janimo/textsecure/protobuf"
	"gopkg.in/yaml.v2"
)

// Group holds group metadata
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
func setupGroups() {
	groupDir = filepath.Join(storageDir, "groups")
	os.MkdirAll(groupDir, 0700)
	filepath.Walk(groupDir, func(path string, fi os.FileInfo, err error) error {
		if !fi.IsDir() {
			if !strings.Contains(path, "avatar") {
				loadGroup(path)
			}
		}
		return nil

	})
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
func updateGroup(gr *textsecure.PushMessageContent_GroupContext) error {
	hexid := idToHex(gr.GetId())

	if av := gr.GetAvatar(); av != nil {
		avatarContents, err := handleSingleAttachment(av)
		if err != nil {
			return err
		}
		ioutil.WriteFile(avatarPath(hexid), avatarContents, 0600)
	}

	groups[hexid] = &Group{
		ID:      gr.GetId(),
		Name:    gr.GetName(),
		Members: gr.GetMembers(),
	}
	return saveGroup(hexid)
}

// quitGroup removes a quitting member from the local group state.
func quitGroup(src string, hexid string) error {
	gr, ok := groups[hexid]
	if !ok {
		return fmt.Errorf("Quit message for group with unknown ID %s\n", hexid)
	}

	gr.Members = removeMember(src, gr.Members)

	return saveGroup(hexid)
}

// handleGroups is the main entry point for handling the group metadata on messages.
func handleGroups(src string, pmc *textsecure.PushMessageContent) (string, error) {
	gr := pmc.GetGroup()
	if gr == nil {
		return "", nil
	}
	hexid := idToHex(gr.GetId())

	switch gr.GetType() {
	case textsecure.PushMessageContent_GroupContext_UPDATE:
		if err := updateGroup(gr); err != nil {
			return "", err
		}
	case textsecure.PushMessageContent_GroupContext_DELIVER:
		if g, ok := groups[hexid]; ok {
			return g.Name, nil
		}
		return "", fmt.Errorf("Unknown group ID %s\n", hexid)
	case textsecure.PushMessageContent_GroupContext_QUIT:
		if err := quitGroup(src, hexid); err != nil {
			return "", err
		}
	}

	return "", nil
}

// SendGroupMessage sends a text message to a given group.
func SendGroupMessage(name string, msg string) error {
	g := groupByName(name)
	if g == nil {
		return fmt.Errorf("Unknown group %s\n", name)
	}
	for _, m := range g.Members {
		if m != config.Tel {
			sendMessage(m, msg, g.ID, nil)
		}
	}
	return nil
}
