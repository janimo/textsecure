// Copyright (c) 2014 Canonical Ltd.
// Licensed under the GPLv3, see the COPYING file for details.

package textsecure

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/aebruno/textsecure/axolotl"
	"github.com/aebruno/textsecure/protobuf"
	"github.com/golang/protobuf/proto"

	log "github.com/sirupsen/logrus"
)

var (
	createAccountPath      = "/v1/accounts/%s/code/%s?client=%s"
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
/**
 * Verify a Signal Service account with a received SMS or voice verification code.
 *
 * @param verificationCode The verification code received via SMS or Voice
 *                         (see {@link #requestSmsVerificationCode} and
 *                         {@link #requestVoiceVerificationCode}).
 * @param signalingKey 52 random bytes.  A 32 byte AES key and a 20 byte Hmac256 key,
 *                     concatenated.
 * @param signalProtocolRegistrationId A random 14-bit number that identifies this Signal install.
 *                                     This value should remain consistent across registrations for the
 *                                     same install, but probabilistically differ across registrations
 *                                     for separate installs.
 *
 * @throws IOException
 */
type RegistrationInfo struct {
	password       string
	registrationID uint32
	signalingKey   []byte
	captchaToken   string
}

var registrationInfo RegistrationInfo

// Registration

func requestCode(tel, method string) (string, error) {
	fmt.Println("request verification code for ", tel)
	resp, err := transport.get(fmt.Sprintf(createAccountPath, method, tel, "android"))
	if err != nil {
		fmt.Println(err.Error())
		return "", err
	}
	if resp.isError() {
		if resp.Status == 402 {
			fmt.Println(resp.Body)
			buf := new(bytes.Buffer)
			buf.ReadFrom(resp.Body)
			newStr := buf.String()
			fmt.Printf(newStr)
			defer resp.Body.Close()

			return "", errors.New("Need to solve captcha")
		} else if resp.Status == 413 {
			fmt.Println(resp.Body)
			buf := new(bytes.Buffer)
			buf.ReadFrom(resp.Body)
			newStr := buf.String()
			fmt.Printf(newStr)
			defer resp.Body.Close()

			return "", errors.New("Rate Limit Exeded")
		} else {
			fmt.Println(resp.Status)
			defer resp.Body.Close()

			return "", errors.New("Error, see logs")
		}
	} else {
		defer resp.Body.Close()
		return "", nil
	}
	// unofficial dev method, useful for development, with no telephony account needed on the server
	// if method == "dev" {
	// 	code := make([]byte, 7)
	// 	l, err := resp.Body.Read(code)
	// 	if err == nil || (err == io.EOF && l == 7) {
	// 		return string(code[:3]) + string(code[4:]), nil
	// 	}
	// 	return "", err
	// }
	// return "", nil
}

type AccountAttributes struct {
	SignalingKey    string `json:"signalingKey"`
	RegistrationID  uint32 `json:"registrationId"`
	FetchesMessages bool   `json:"fetchesMessages"`
	Video           bool   `json:"video"`
	Voice           bool   `json:"voice"`
	// Pin                            *string `json:"pin"`
	// UnidentifiedAccessKey          *byte `json:"unidentifiedAccessKey"`
	// UnrestrictedUnidentifiedAccess *bool `json:"unrestrictedUnidentifiedAccess"`
}
type RegistrationLockFailure struct {
	TimeRemaining      string `json:"timeRemaining"`
	StorageCredentials uint32 `json:"storageCredentials"`
}

func verifyCode(code string) error {
	fmt.Println("code1: " + code)

	code = strings.Replace(code, "-", "", -1)

	vd := AccountAttributes{
		SignalingKey:    base64.StdEncoding.EncodeToString(registrationInfo.signalingKey),
		RegistrationID:  registrationInfo.registrationID,
		FetchesMessages: true,
		Voice:           false,
		Video:           false,
		// Pin:             nil,
		// UnidentifiedAccessKey:          nil,
		// UnrestrictedUnidentifiedAccess: nil,
	}
	body, err := json.Marshal(vd)
	if err != nil {
		return err
	}
	resp, err := transport.putJSON(fmt.Sprintf(verifyAccountPath, code), body)
	if err != nil {
		fmt.Println(err.Error())
		return err
	}
	if resp.isError() {

		if resp.Status == 423 {
			buf := new(bytes.Buffer)
			buf.ReadFrom(resp.Body)
			newStr := buf.String()
			// fmt.Printf(newStr)
			// v := RegistrationLockFailure{}
			// err := json.NewDecoder(resp.Body).Decode(&v)
			// if err != nil {
			// 	return err
			// }
			return errors.New(fmt.Sprintf("RegistrationLockFailure \n Time to wait \n %s", newStr))
		} else {
			return resp
		}
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

	pm := &signalservice.ProvisionMessage{
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
	Content            string `json:"content"`
	Relay              string `json:"relay,omitempty"`
}

func createMessage(msg *outgoingMessage) *signalservice.DataMessage {
	dm := &signalservice.DataMessage{}
	if msg.msg != "" {
		dm.Body = &msg.msg
	}
	if msg.attachment != nil {
		dm.Attachments = []*signalservice.AttachmentPointer{
			{
				Id:          &msg.attachment.id,
				ContentType: &msg.attachment.ct,
				Key:         msg.attachment.keys[:],
				Digest:      msg.attachment.digest[:],
				Size:        &msg.attachment.size,
			},
		}
	}
	if msg.group != nil {
		dm.Group = &signalservice.GroupContext{
			Id:      msg.group.id,
			Type:    &msg.group.typ,
			Name:    &msg.group.name,
			Members: msg.group.members,
		}
	}

	dm.Flags = &msg.flags

	return dm
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

func buildMessage(tel string, paddedMessage []byte, devices []uint32, isSync bool) ([]jsonMessage, error) {
	recid := recID(tel)
	messages := []jsonMessage{}

	for _, devid := range devices {
		if !textSecureStore.ContainsSession(recid, devid) {
			pkb, err := makePreKeyBundle(tel, devid)
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

		jmsg := jsonMessage{
			Type:               messageType,
			DestDeviceID:       devid,
			DestRegistrationID: rrID,
		}

		jmsg.Content = base64.StdEncoding.EncodeToString(encryptedMessage)
		messages = append(messages, jmsg)
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

type sendMessageResponse struct {
	NeedsSync bool   `json:"needsSync"`
	Timestamp uint64 `json:"-"`
}

// ErrRemoteGone is returned when the peer reinstalled and lost its session state.
var ErrRemoteGone = errors.New("the remote device is gone (probably reinstalled)")

var deviceLists = map[string][]uint32{}

func buildAndSendMessage(tel string, paddedMessage []byte, isSync bool) (*sendMessageResponse, error) {
	bm, err := buildMessage(tel, paddedMessage, deviceLists[tel], isSync)
	if err != nil {
		return nil, err
	}
	m := make(map[string]interface{})
	m["messages"] = bm
	now := uint64(time.Now().UnixNano() / 1000000)
	m["timestamp"] = now
	m["destination"] = tel
	body, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	resp, err := transport.putJSON(fmt.Sprintf(messagePath, tel), body)
	if err != nil {
		return nil, err
	}

	if resp.Status == mismatchedDevicesStatus {
		dec := json.NewDecoder(resp.Body)
		var j jsonMismatchedDevices
		dec.Decode(&j)
		log.Debugf("Mismatched devices: %+v\n", j)
		devs := []uint32{}
		for _, id := range deviceLists[tel] {
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
		deviceLists[tel] = append(devs, j.MissingDevices...)
		return buildAndSendMessage(tel, paddedMessage, isSync)
	}
	if resp.Status == staleDevicesStatus {
		dec := json.NewDecoder(resp.Body)
		var j jsonStaleDevices
		dec.Decode(&j)
		log.Debugf("Stale devices: %+v\n", j)
		for _, id := range j.StaleDevices {
			textSecureStore.DeleteSession(recID(tel), id)
		}
		return buildAndSendMessage(tel, paddedMessage, isSync)
	}
	if resp.isError() {
		return nil, resp
	}

	var smRes sendMessageResponse
	dec := json.NewDecoder(resp.Body)
	dec.Decode(&smRes)
	smRes.Timestamp = now

	log.Debugf("SendMessageResponse: %+v\n", smRes)
	return &smRes, nil
}

func sendMessage(msg *outgoingMessage) (uint64, error) {
	if _, ok := deviceLists[msg.tel]; !ok {
		deviceLists[msg.tel] = []uint32{1}
	}

	dm := createMessage(msg)

	content := &signalservice.Content{
		DataMessage: dm,
	}

	b, err := proto.Marshal(content)
	if err != nil {
		return 0, err
	}

	resp, err := buildAndSendMessage(msg.tel, padMessage(b), false)
	if err != nil {
		return 0, err
	}

	if resp.NeedsSync {
		log.Debugf("Needs sync. destination: %s", msg.tel)
		sm := &signalservice.SyncMessage{
			Sent: &signalservice.SyncMessage_Sent{
				Destination: &msg.tel,
				Timestamp:   &resp.Timestamp,
				Message:     dm,
			},
		}

		_, serr := sendSyncMessage(sm)
		if serr != nil {
			log.WithFields(log.Fields{
				"error":       serr,
				"destination": msg.tel,
				"timestamp":   resp.Timestamp,
			}).Error("Failed to send sync message")
		}
	}

	return resp.Timestamp, err
}

func sendSyncMessage(sm *signalservice.SyncMessage) (uint64, error) {
	if _, ok := deviceLists[config.Tel]; !ok {
		deviceLists[config.Tel] = []uint32{1}
	}

	content := &signalservice.Content{
		SyncMessage: sm,
	}

	b, err := proto.Marshal(content)
	if err != nil {
		return 0, err
	}

	resp, err := buildAndSendMessage(config.Tel, padMessage(b), true)
	return resp.Timestamp, err
}
