// Copyright (c) 2014 Canonical Ltd.
// Licensed under the GPLv3, see the COPYING file for details.

package textsecure

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/golang/protobuf/proto"
	"github.com/janimo/textsecure/axolotl"
	"github.com/janimo/textsecure/protobuf"
)

var (
	createAccountPath = "/v1/accounts/%/code/%s"
	verifyAccountPath = "/v1/accounts/code/%s"

	prekeyMetadataPath = "/v2/keys/"
	prekeyPath         = "/v2/keys/%s"
	prekeyDevicePath   = "/v2/keys/%s/%s"
	signedPrekeyPath   = "/v2/keys/signed"

	provisioningCodePath    = "/v1/devices/provisioning/code"
	provisioningMessagePath = "/v1/provisioning/%s"

	directoryTokensPath    = "/v1/directory/tokens"
	directoryVerifyPath    = "/v1/directory/%s"
	messagePath            = "/v1/messages/%s"
	acknowledgeMessagePath = "/v1/messages/%s/%d"
	receiptPath            = "/v1/receipt/%s/%d"
	attachmentPath         = "/v1/attachments/%s"
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
func registerPreKeys() error {
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
		return nil, fmt.Errorf("Could not get local contacts :%s\n", err)
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

func createMessage(msg *outgoingMessage) ([]byte, error) {
	pmc := &textsecure.PushMessageContent{}
	if msg.msg != "" {
		pmc.Body = &msg.msg
	}
	if msg.attachment != nil {
		pmc.Attachments = []*textsecure.PushMessageContent_AttachmentPointer{
			&textsecure.PushMessageContent_AttachmentPointer{
				Id:          &msg.attachment.id,
				ContentType: &msg.attachment.ct,
				Key:         msg.attachment.keys,
			},
		}
	}
	if msg.group != nil {
		pmc.Group = &textsecure.PushMessageContent_GroupContext{
			Id:      msg.group.id,
			Type:    &msg.group.typ,
			Name:    &msg.group.name,
			Members: msg.group.members,
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

func buildMessage(msg *outgoingMessage) ([]jsonMessage, error) {
	devid := uint32(1) //FIXME: support multiple destination devices
	paddedMessage, err := createMessage(msg)
	if err != nil {
		return nil, err
	}
	recid := recID(msg.tel)
	if !textSecureStore.ContainsSession(recid, devid) {
		pkb, err := makePreKeyBundle(msg.tel)
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

func sendMessage(msg *outgoingMessage) error {
	m := make(map[string]interface{})
	bm, err := buildMessage(msg)
	if err != nil {
		return err
	}
	m["messages"] = bm
	m["destination"] = msg.tel
	body, err := json.MarshalIndent(m, "", "    ")
	if err != nil {
		return err
	}
	resp, err := transport.putJSON("/v1/messages/"+msg.tel, body)
	if err != nil {
		return err
	}
	if resp.Status == 410 {
		textSecureStore.DeleteSession(recID(msg.tel), uint32(1))
		return errors.New("The remote device is gone (probably reinstalled)")
	}
	if resp.isError() {
		return resp
	}
	return nil
}
