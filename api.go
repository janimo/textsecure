// Copyright (c) 2014 Canonical Ltd.
// Licensed under the GPLv3, see the COPYING file for details.

package textsecure

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"

	"github.com/golang/protobuf/proto"
	"github.com/janimo/textsecure/axolotl"
	"github.com/janimo/textsecure/protobuf"
)

// RegistrationInfo holds the data required to be identified by and
// to communicate with the push server.
// The data is generated once at install time and stored locally.
type RegistrationInfo struct {
	password       string
	registrationID uint32
	signalingKey   []byte
}

var registrationInfo RegistrationInfo

// Registration

func requestCode(tel, method string) (string, error) {
	resp, err := transport.get(fmt.Sprintf("/v1/accounts/%s/code/%s", method, tel))
	if err != nil {
		return "", err
	}
	// unofficial dev method, useful for development, with no telephony account needed on the server
	if method == "dev" {
		code := make([]byte, 7)
		_, err = resp.Body.Read(code)
		if err != nil {
			return "", err
		}
		return string(code[:3]) + string(code[4:]), nil
	}
	return "", nil
}

type verificationData struct {
	SignalingKey    string `json:"signalingKey"`
	RegistrationID  uint32 `json:"registrationId"`
	SupportsSms     bool   `json:"supportSms"`
	FetchesMessages bool   `json:"fetchesMessages"`
}

func verifyCode(code string) error {
	vd := verificationData{
		SignalingKey:    base64.StdEncoding.EncodeToString(registrationInfo.signalingKey),
		SupportsSms:     false,
		FetchesMessages: true,
		RegistrationID:  registrationInfo.registrationID,
	}
	body, err := json.Marshal(vd)
	if err != nil {
		return err
	}
	resp, err := transport.putJSON("/v1/accounts/code/"+code, body)
	if err != nil {
		return err
	}
	if resp.isError() {
		return resp
	}
	return nil
}

// PUT /v2/keys/
func registerPreKeys2() error {
	body, err := json.MarshalIndent(preKeys, "", "")
	if err != nil {
		return err
	}

	resp, err := transport.putJSON("/v2/keys/", body)
	if err != nil {
		return err
	}
	if resp.isError() {
		return resp
	}
	return nil
}

// GET /v2/keys/{number}/{device_id}?relay={relay}
func getPreKeys(tel string) (*preKeyResponse, error) {
	resp, err := transport.get(fmt.Sprintf("/v2/keys/%s/*", tel))
	if err != nil {
		return nil, err
	}
	if resp.isError() {
		return nil, fmt.Errorf("HTTP error %d\n", resp.Status)
	}
	dec := json.NewDecoder(resp.Body)
	k := &preKeyResponse{}
	dec.Decode(k)
	return k, nil
}

// jsonContact is the data returned by the server for each registered contact
type jsonContact struct {
	Token       string `json:"token"`
	Relay       string `json:"relay"`
	SupportsSms bool   `json:"supportsSms"`
}

// GetRegisteredContacts returns the subset of the local contacts
// that are also registered with the server
func GetRegisteredContacts() ([]Contact, error) {
	lc, err := loadLocalContacts()
	if err != nil {
		log.Printf("Could not get local contacts :%s\n", err)
		return nil, err
	}
	tokens := make([]string, len(lc))
	m := make(map[string]Contact)
	for i, c := range lc {
		t := telToToken(c.Tel)
		tokens[i] = t
		m[t] = c
	}

	contacts := make(map[string][]string)
	contacts["contacts"] = tokens
	body, err := json.MarshalIndent(contacts, "", "    ")
	if err != nil {
		return nil, err
	}
	resp, err := transport.putJSON("/v1/directory/tokens/", body)
	if err != nil {
		return nil, err
	}
	if resp.isError() {
		return nil, resp
	}
	dec := json.NewDecoder(resp.Body)
	var jc map[string][]jsonContact
	dec.Decode(&jc)

	lc = make([]Contact, len(jc["contacts"]))
	for i, c := range jc["contacts"] {
		lc[i] = m[c.Token]
	}
	return lc, nil
}

// Attachment handling

type jsonAllocation struct {
	ID       uint64 `json:"id"`
	Location string `json:"location"`
}

func confirmReceipt(source string, timestamp uint64) {
	transport.putJSON(fmt.Sprintf("/v1/receipt/%s/%d", source, timestamp), nil)
}

// GET /v1/attachments/
func allocateAttachment() (uint64, string, error) {
	resp, err := transport.get("/v1/attachments")
	if err != nil {
		return 0, "", err
	}
	dec := json.NewDecoder(resp.Body)
	var a jsonAllocation
	dec.Decode(&a)
	return a.ID, a.Location, nil
}

func getAttachmentLocation(id uint64) (string, error) {
	resp, err := transport.get(fmt.Sprintf("/v1/attachments/%d", id))
	if err != nil {
		return "", err
	}
	dec := json.NewDecoder(resp.Body)
	var a jsonAllocation
	dec.Decode(&a)
	return a.Location, nil
}

// Messages

type jsonMessage struct {
	Type               int32  `json:"type"`
	DestDeviceID       uint32 `json:"destinationDeviceId"`
	DestRegistrationID uint32 `json:"destinationRegistrationId"`
	Body               string `json:"body"`
	Relay              string `json:"relay,omitempty"`
}

func createMessage(msg string, groupID []byte, a *att) ([]byte, error) {
	pmc := &textsecure.PushMessageContent{}
	if msg != "" {
		pmc.Body = &msg
	}
	if a != nil {
		pmc.Attachments = []*textsecure.PushMessageContent_AttachmentPointer{
			&textsecure.PushMessageContent_AttachmentPointer{
				Id:          &a.id,
				ContentType: &a.ct,
				Key:         a.keys,
			},
		}
	}
	if groupID != nil {
		typ := textsecure.PushMessageContent_GroupContext_DELIVER
		pmc.Group = &textsecure.PushMessageContent_GroupContext{
			Type: &typ,
			Id:   groupID,
		}
	}
	b, err := proto.Marshal(pmc)
	if err != nil {
		return nil, err
	}
	return padMessage(b), nil
}

func padMessage(msg []byte) []byte {
	l := (len(msg) + 160)
	l = l - l%160
	n := make([]byte, l)
	copy(n, msg)
	n[len(msg)] = 0x80
	return n
}

func stripPadding(msg []byte) []byte {
	for i := len(msg) - 1; i >= 0; i-- {
		if msg[i] == 0x80 {
			return msg[:i]
		}
	}
	return msg
}

func makePreKeyBundle(tel string) (*axolotl.PreKeyBundle, error) {
	pkr, err := getPreKeys(tel)
	if err != nil {
		return nil, err
	}

	ndev := len(pkr.Devices)

	pkbs := make([]*axolotl.PreKeyBundle, ndev)

	for i, d := range pkr.Devices {
		decPK, err := decodeKey(d.PreKey.PublicKey)
		if err != nil {
			return nil, err
		}

		decSPK, err := decodeKey(d.SignedPreKey.PublicKey)
		if err != nil {
			return nil, err
		}

		decSig, err := decodeSignature(d.SignedPreKey.Signature)
		if err != nil {
			return nil, err
		}

		decIK, err := decodeKey(pkr.IdentityKey)
		if err != nil {
			return nil, err
		}

		pkbs[i], err = axolotl.NewPreKeyBundle(
			d.RegistrationID, d.DeviceID, d.PreKey.ID,
			axolotl.NewECPublicKey(decPK), int32(d.SignedPreKey.ID), axolotl.NewECPublicKey(decSPK),
			decSig, axolotl.NewIdentityKey(decIK))
		if err != nil {
			return nil, err
		}
	}

	return pkbs[0], nil
}

type att struct {
	id   uint64
	ct   string
	keys []byte
}

func buildMessage(tel string, msg string, groupID []byte, a *att) ([]jsonMessage, error) {
	devid := uint32(1) //FIXME: support multiple destination devices
	paddedMessage, err := createMessage(msg, groupID, a)
	if err != nil {
		return nil, err
	}
	recid := recID(tel)
	if !textSecureStore.ContainsSession(recid, devid) {
		pkb, err := makePreKeyBundle(tel)
		if err != nil {
			return nil, err
		}
		sb := axolotl.NewSessionBuilder(textSecureStore, textSecureStore, textSecureStore, textSecureStore, recid, pkb.DeviceID)
		err = sb.BuildSenderSession(pkb)
		if err != nil {
			return nil, err
		}
	}
	sc := axolotl.NewSessionCipher(textSecureStore, textSecureStore, textSecureStore, textSecureStore, recid, devid)
	encryptedMessage, messageType, err := sc.SessionEncryptMessage(paddedMessage)
	if err != nil {
		return nil, err
	}

	rrID, err := sc.GetRemoteRegistrationID()
	if err != nil {
		return nil, err
	}
	messages := []jsonMessage{{
		Type:               messageType,
		DestDeviceID:       devid,
		DestRegistrationID: rrID,
		Body:               base64.StdEncoding.EncodeToString(encryptedMessage),
	}}
	return messages, nil
}

func sendMessage(tel, msg string, groupID []byte, a *att) error {
	m := make(map[string]interface{})
	bm, err := buildMessage(tel, msg, groupID, a)
	if err != nil {
		return err
	}
	m["messages"] = bm
	m["destination"] = tel
	body, err := json.MarshalIndent(m, "", "    ")
	if err != nil {
		return err
	}
	resp, err := transport.putJSON("/v1/messages/"+tel, body)
	if err != nil {
		return err
	}
	if resp.Status == 410 {
		textSecureStore.DeleteSession(recID(tel), uint32(1))
		return errors.New("The remote device is gone (probably reinstalled)")
	}
	if resp.isError() {
		return resp
	}
	return nil
}
