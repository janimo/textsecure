// Copyright (c) 2014 Canonical Ltd.
// Licensed under the GPLv3, see the COPYING file for details.

package textsecure

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/janimo/textsecure/axolotl"
	"github.com/janimo/textsecure/protobuf"

	log "github.com/Sirupsen/logrus"
)

var (
	createAccountPath      = "/v1/accounts/%s/code/%s"
	verifyAccountPath      = "/v1/accounts/code/%s"
	registerUPSAccountPath = "/v1/accounts/ups/"

	prekeyMetadataPath = "/v2/keys/"
	prekeyPath         = "/v2/keys/%s"
	prekeyDevicePath   = "/v2/keys/%s/%s"
	signedPrekeyPath   = "/v2/keys/signed"

	provisioningCodePath    = "/v1/devices/provisioning/code"
	provisioningMessagePath = "/v1/provisioning/%s"
	devicePath              = "/v1/devices/%s"

	directoryTokensPath    = "/v1/directory/tokens"
	directoryVerifyPath    = "/v1/directory/%s"
	messagePath            = "/v1/messages/%s"
	acknowledgeMessagePath = "/v1/messages/%s/%d"
	receiptPath            = "/v1/receipt/%s/%d"
	allocateAttachmentPath = "/v1/attachments/"
	attachmentPath         = "/v1/attachments/%d"
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
	resp, err := transport.get(fmt.Sprintf(createAccountPath, method, tel))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	// unofficial dev method, useful for development, with no telephony account needed on the server
	if method == "dev" {
		code := make([]byte, 7)
		l, err := resp.Body.Read(code)
		if err == nil || (err == io.EOF && l == 7) {
			return string(code[:3]) + string(code[4:]), nil
		}
		return "", err
	}
	return "", nil
}

type verificationData struct {
	SignalingKey    string `json:"signalingKey"`
	RegistrationID  uint32 `json:"registrationId"`
	FetchesMessages bool   `json:"fetchesMessages"`
}

func verifyCode(code string) error {
	code = strings.Replace(code, "-", "", -1)
	vd := verificationData{
		SignalingKey:    base64.StdEncoding.EncodeToString(registrationInfo.signalingKey),
		FetchesMessages: true,
		RegistrationID:  registrationInfo.registrationID,
	}
	body, err := json.Marshal(vd)
	if err != nil {
		return err
	}
	resp, err := transport.putJSON(fmt.Sprintf(verifyAccountPath, code), body)
	if err != nil {
		return err
	}
	if resp.isError() {
		return resp
	}
	return nil
}

type upsRegistration struct {
	UPSRegistrationID string `json:"upsRegistrationId"`
}

// RegisterWithUPS registers our Ubuntu push client token with the server.
func RegisterWithUPS(token string) error {
	reg := upsRegistration{
		UPSRegistrationID: token,
	}
	body, err := json.Marshal(reg)
	if err != nil {
		return err
	}
	resp, err := transport.putJSON(registerUPSAccountPath, body)
	if err != nil {
		return err
	}
	if resp.isError() {
		return resp
	}
	return nil
}

type jsonDeviceCode struct {
	VerificationCode string `json:"verificationCode"`
}

func getNewDeviceVerificationCode() (string, error) {
	resp, err := transport.get(provisioningCodePath)
	if err != nil {
		return "", err
	}
	dec := json.NewDecoder(resp.Body)
	var c jsonDeviceCode
	dec.Decode(&c)
	return c.VerificationCode, nil
}

type DeviceInfo struct {
	ID       uint32 `json:"id"`
	Name     string `json:"name"`
	Created  uint64 `json:"created"`
	LastSeen uint64 `json:"lastSeen"`
}

func getLinkedDevices() ([]DeviceInfo, error) {
	type jsonDevices struct {
		DeviceList []DeviceInfo `json:"devices"`
	}
	devices := &jsonDevices{}

	resp, err := transport.get(fmt.Sprintf(devicePath, ""))
	if err != nil {
		return devices.DeviceList, err
	}

	dec := json.NewDecoder(resp.Body)
	err = dec.Decode(&devices)
	if err != nil {
		return devices.DeviceList, nil
	}

	return devices.DeviceList, nil
}

func unlinkDevice(id int) error {
	_, err := transport.del(fmt.Sprintf(devicePath, strconv.Itoa(id)))
	if err != nil {
		return err
	}
	return nil
}

func addNewDevice(ephemeralId, publicKey, verificationCode string) error {
	decPk, err := decodeKey(publicKey)
	if err != nil {
		return err
	}

	theirPublicKey := axolotl.NewECPublicKey(decPk)

	pm := &textsecure.ProvisionMessage{
		IdentityKeyPublic:  identityKey.PublicKey.Serialize(),
		IdentityKeyPrivate: identityKey.PrivateKey.Key()[:],
		Number:             &config.Tel,
		ProvisioningCode:   &verificationCode,
	}

	ciphertext, err := provisioningCipher(pm, theirPublicKey)
	if err != nil {
		return err
	}

	jsonBody := make(map[string]string)
	jsonBody["body"] = base64.StdEncoding.EncodeToString(ciphertext)
	body, err := json.Marshal(jsonBody)
	if err != nil {
		return err
	}

	url := fmt.Sprintf(provisioningMessagePath, ephemeralId)
	resp, err := transport.putJSON(url, body)
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

	resp, err := transport.putJSON(prekeyMetadataPath, body)
	if err != nil {
		return err
	}
	if resp.isError() {
		return resp
	}
	return nil
}

// GET /v2/keys/{number}/{device_id}?relay={relay}
func getPreKeys(tel string, deviceID string) (*preKeyResponse, error) {
	resp, err := transport.get(fmt.Sprintf(prekeyDevicePath, tel, deviceID))
	if err != nil {
		return nil, err
	}
	if resp.isError() {
		return nil, resp
	}
	dec := json.NewDecoder(resp.Body)
	k := &preKeyResponse{}
	dec.Decode(k)
	return k, nil
}

// jsonContact is the data returned by the server for each registered contact
type jsonContact struct {
	Token string `json:"token"`
	Relay string `json:"relay"`
}

// GetRegisteredContacts returns the subset of the local contacts
// that are also registered with the server
func GetRegisteredContacts() ([]Contact, error) {
	lc, err := client.GetLocalContacts()
	if err != nil {
		return nil, fmt.Errorf("could not get local contacts :%s\n", err)
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
	resp, err := transport.putJSON(directoryTokensPath, body)
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
	resp, err := transport.get(allocateAttachmentPath)
	if err != nil {
		return 0, "", err
	}
	dec := json.NewDecoder(resp.Body)
	var a jsonAllocation
	dec.Decode(&a)
	return a.ID, a.Location, nil
}

func getAttachmentLocation(id uint64) (string, error) {
	resp, err := transport.get(fmt.Sprintf(attachmentPath, id))
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
	Content            string `json:"content"`
	Relay              string `json:"relay,omitempty"`
}

func createMessage(msg *outgoingMessage) ([]byte, error) {
	dm := &textsecure.DataMessage{}
	if msg.msg != "" {
		dm.Body = &msg.msg
	}
	if msg.attachment != nil {
		dm.Attachments = []*textsecure.AttachmentPointer{
			{
				Id:          &msg.attachment.id,
				ContentType: &msg.attachment.ct,
				Key:         msg.attachment.keys,
			},
		}
	}
	if msg.group != nil {
		dm.Group = &textsecure.GroupContext{
			Id:      msg.group.id,
			Type:    &msg.group.typ,
			Name:    &msg.group.name,
			Members: msg.group.members,
		}
	}

	dm.Flags = &msg.flags

	b, err := proto.Marshal(dm)
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

func makePreKeyBundle(tel string, deviceID uint32) (*axolotl.PreKeyBundle, error) {
	pkr, err := getPreKeys(tel, strconv.Itoa(int(deviceID)))
	if err != nil {
		return nil, err
	}

	if len(pkr.Devices) != 1 {
		return nil, fmt.Errorf("no prekeys for contact %s, device %d\n", tel, deviceID)
	}

	d := pkr.Devices[0]

	if d.PreKey == nil {
		return nil, fmt.Errorf("no prekey for contact %s, device %d\n", tel, deviceID)
	}

	decPK, err := decodeKey(d.PreKey.PublicKey)
	if err != nil {
		return nil, err
	}

	if d.SignedPreKey == nil {
		return nil, fmt.Errorf("no signed prekey for contact %s, device %d\n", tel, deviceID)
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

	pkb, err := axolotl.NewPreKeyBundle(
		d.RegistrationID, d.DeviceID, d.PreKey.ID,
		axolotl.NewECPublicKey(decPK), int32(d.SignedPreKey.ID), axolotl.NewECPublicKey(decSPK),
		decSig, axolotl.NewIdentityKey(decIK))
	if err != nil {
		return nil, err
	}

	return pkb, nil
}

func buildMessage(msg *outgoingMessage, devices []uint32) ([]jsonMessage, error) {
	paddedMessage, err := createMessage(msg)
	if err != nil {
		return nil, err
	}
	recid := recID(msg.tel)
	messages := []jsonMessage{}

	for _, devid := range devices {
		if !textSecureStore.ContainsSession(recid, devid) {
			pkb, err := makePreKeyBundle(msg.tel, devid)
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
		messages = append(messages, jsonMessage{
			Type:               messageType,
			DestDeviceID:       devid,
			DestRegistrationID: rrID,
			Body:               base64.StdEncoding.EncodeToString(encryptedMessage),
		})
	}

	return messages, nil
}

var (
	mismatchedDevicesStatus = 409
	staleDevicesStatus      = 410
	rateLimitExceededStatus = 413
)

type jsonMismatchedDevices struct {
	MissingDevices []uint32 `json:"missingDevices"`
	ExtraDevices   []uint32 `json:"extraDevices"`
}

type jsonStaleDevices struct {
	StaleDevices []uint32 `json:"staleDevices"`
}

// ErrRemoteGone is returned when the peer reinstalled and lost its session state.
var ErrRemoteGone = errors.New("the remote device is gone (probably reinstalled)")

var deviceLists = map[string][]uint32{}

func buildAndSendMessage(msg *outgoingMessage) (uint64, error) {
	bm, err := buildMessage(msg, deviceLists[msg.tel])
	if err != nil {
		return 0, err
	}
	m := make(map[string]interface{})
	m["messages"] = bm
	now := uint64(time.Now().UnixNano() / 1000000)
	m["timestamp"] = now
	m["destination"] = msg.tel
	body, err := json.MarshalIndent(m, "", "    ")
	if err != nil {
		return 0, err
	}
	resp, err := transport.putJSON(fmt.Sprintf(messagePath, msg.tel), body)
	if err != nil {
		return 0, err
	}
	if resp.Status == mismatchedDevicesStatus {
		dec := json.NewDecoder(resp.Body)
		var j jsonMismatchedDevices
		dec.Decode(&j)
		log.Debugf("Mismatched devices: %+v\n", j)
		devs := []uint32{}
		for _, id := range deviceLists[msg.tel] {
			in := true
			for _, eid := range j.ExtraDevices {
				if id == eid {
					in = false
					break
				}
			}
			if in {
				devs = append(devs, id)
			}
		}
		deviceLists[msg.tel] = append(devs, j.MissingDevices...)
		return buildAndSendMessage(msg)
	}
	if resp.Status == staleDevicesStatus {
		dec := json.NewDecoder(resp.Body)
		var j jsonStaleDevices
		dec.Decode(&j)
		log.Debugf("Stale devices: %+v\n", j)
		for _, id := range j.StaleDevices {
			textSecureStore.DeleteSession(recID(msg.tel), id)
		}
		return buildAndSendMessage(msg)
	}
	if resp.isError() {
		return 0, resp
	}
	return now, nil
}

func sendMessage(msg *outgoingMessage) (uint64, error) {
	if _, ok := deviceLists[msg.tel]; !ok {
		deviceLists[msg.tel] = []uint32{1}
	}
	ts, err := buildAndSendMessage(msg)
	return ts, err
}
