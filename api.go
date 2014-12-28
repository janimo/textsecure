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

// Registration holds the data required to be identified by and
// to communicate with the push server.
// The data is generated once at install time and stored locally.
type RegistrationInfo struct {
	password       string
	registrationId uint32
	signalingKey   []byte
}

var registrationInfo RegistrationInfo

// Registration

func requestCode(tel, transport string) string {
	resp, err := transporter.Get(fmt.Sprintf("/v1/accounts/%s/code/%s", transport, tel))
	if err != nil {
		log.Fatal(err)
	}
	// unofficial dev transport, useful for development, with no telephony account needed on the server
	if transport == "dev" {
		code := make([]byte, 7)
		_, err = resp.Body.Read(code)
		if err != nil {
			log.Fatal(err)
		}
		return string(code[:3]) + string(code[4:])
	}
	return ""
}

type verificationData struct {
	SignalingKey    string `json:"signalingKey"`
	RegistrationId  uint32 `json:"registrationId"`
	SupportsSms     bool   `json:"supportSms"`
	FetchesMessages bool   `json:"fetchesMessages"`
}

func verifyCode(code string) {
	vd := verificationData{
		SignalingKey:    base64.StdEncoding.EncodeToString(registrationInfo.signalingKey),
		SupportsSms:     false,
		FetchesMessages: true,
		RegistrationId:  registrationInfo.registrationId,
	}
	body, err := json.Marshal(vd)
	if err != nil {
		log.Fatal(err)
	}
	transporter.PutJSON("/v1/accounts/code/"+code, body)
}

// PUT /v2/keys/
func registerPreKeys2() {
	body, err := json.MarshalIndent(preKeys, "", "")
	if err != nil {
		log.Fatal(err)
	}

	_, err = transporter.PutJSON("/v2/keys/", body)
	if err != nil {
		log.Fatal(err)
	}
}

// GET /v2/keys/{number}/{device_id}?relay={relay}
func getPreKeys(tel string) (*PreKeyResponse, error) {
	resp, err := transporter.Get(fmt.Sprintf("/v2/keys/%s/*", tel))
	if err != nil {
		return nil, err
	}
	if resp.isError() {
		return nil, fmt.Errorf("HTTP error %d\n", resp.Status)
	}
	dec := json.NewDecoder(resp.Body)
	k := &PreKeyResponse{}
	dec.Decode(k)
	return k, nil
}

// JSONContact is the data returned by the server for each registered contact
type JSONContact struct {
	Token       string `json:"token"`
	Relay       string `json:"relay"`
	SupportsSms bool   `json:"supportsSms"`
}

// GetRegisteredContacts returns the subset of the local contacts
// that are also registered with the server
func GetRegisteredContacts() []Contact {
	lc, err := loadLocalContacts()
	if err != nil {
		log.Printf("Coult not get local contacts :%s\n", err)
		return nil
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
		log.Fatal(err)
	}
	resp, err := transporter.PutJSON("/v1/directory/tokens/", body)
	if err != nil {
		log.Fatal(err)
	}
	dec := json.NewDecoder(resp.Body)
	var jc map[string][]JSONContact
	dec.Decode(&jc)

	lc = make([]Contact, len(jc["contacts"]))
	for i, c := range jc["contacts"] {
		lc[i] = m[c.Token]
	}
	return lc
}

// Attachment handling

type JSONAllocation struct {
	Id       uint64 `json:"id"`
	Location string `json:"location"`
}

func confirmReceipt(source string, timestamp uint64) {
	transporter.PutJSON(fmt.Sprintf("/v1/receipt/%s/%d", source, timestamp), nil)
}

// GET /v1/attachments/
func allocateAttachment() (uint64, string, error) {
	resp, err := transporter.Get("/v1/attachments")
	if err != nil {
		return 0, "", err
	}
	dec := json.NewDecoder(resp.Body)
	var a JSONAllocation
	dec.Decode(&a)
	return a.Id, a.Location, nil
}

func getAttachmentLocation(id uint64) (string, error) {
	resp, err := transporter.Get(fmt.Sprintf("/v1/attachments/%d", id))
	if err != nil {
		return "", err
	}
	dec := json.NewDecoder(resp.Body)
	var a JSONAllocation
	dec.Decode(&a)
	return a.Location, nil
}

// Messages

type JSONMessage struct {
	Type               int32  `json:"type"`
	DestDeviceId       uint32 `json:"destinationDeviceId"`
	DestRegistrationId uint32 `json:"destinationRegistrationId"`
	Body               string `json:"body"`
	Relay              string `json:"relay,omitempty"`
}

func canMessage(msg string, a *att) []byte {
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
	b, err := proto.Marshal(pmc)
	if err != nil {
		log.Fatal(err)
	}
	return b
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
		pkbs[i], err = axolotl.NewPreKeyBundle(d.RegistrationId, d.DeviceID,
			d.PreKey.Id, axolotl.NewECPublicKey(decodeKey(d.PreKey.PublicKey)),
			int32(d.SignedPreKey.Id), axolotl.NewECPublicKey(decodeKey(d.SignedPreKey.PublicKey)),
			decodeSignature(d.SignedPreKey.Signature),
			axolotl.NewIdentityKey(decodeKey(pkr.IdentityKey)))
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

func buildMessage(tel string, msg string, a *att) ([]JSONMessage, error) {
	devid := uint32(1) //FIXME: support multiple destination devices
	cannedMsg := canMessage(msg, a)
	paddedMessage := padMessage(cannedMsg)
	recid := recId(tel)
	if !textSecureStore.ContainsSession(recid, devid) {
		pkb, err := makePreKeyBundle(tel)
		if err != nil {
			return nil, err
		}
		sb := axolotl.NewSessionBuilder(textSecureStore, textSecureStore, textSecureStore, textSecureStore, recid, pkb.DeviceId)
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

	messages := []JSONMessage{{
		Type:               messageType,
		DestDeviceId:       devid,
		DestRegistrationId: sc.GetRemoteRegistrationId(),
		Body:               base64.StdEncoding.EncodeToString(encryptedMessage),
	}}
	return messages, nil
}

func sendMessage(tel, msg string) error {
	m := make(map[string]interface{})
	bm, err := buildMessage(tel, msg, nil)
	if err != nil {
		return err
	}
	m["messages"] = bm
	m["destination"] = tel
	body, err := json.MarshalIndent(m, "", "    ")
	if err != nil {
		return err
	}
	resp, err := transporter.PutJSON("/v1/messages/"+tel, body)
	if err != nil {
		return err
	}
	if resp.Status == 410 {
		textSecureStore.DeleteSession(recId(tel), uint32(1))
		return errors.New("The remote device is gone (probably reinstalled)")
	}
	return nil
}

func sendAttachment(tel string, msg string, a *att) error {
	m := make(map[string]interface{})
	bm, err := buildMessage(tel, msg, a)
	if err != nil {
		return err
	}
	m["messages"] = bm
	m["destination"] = tel
	body, err := json.MarshalIndent(m, "", "    ")
	if err != nil {
		return err
	}
	transporter.PutJSON("/v1/messages/"+tel, body)
	return nil
}
