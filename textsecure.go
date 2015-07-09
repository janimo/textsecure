// Copyright (c) 2014 Canonical Ltd.
// Licensed under the GPLv3, see the COPYING file for details.

// Package textsecure implements the TextSecure client protocol.
package textsecure

import (
	"encoding/base64"
	"errors"
	"fmt"
	"mime"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/golang/protobuf/proto"

	log "github.com/Sirupsen/logrus"
	"github.com/janimo/textsecure/axolotl"
	"github.com/janimo/textsecure/protobuf"
)

// Generate a random 16 byte string used for HTTP Basic Authentication to the server
func generatePassword() string {
	b := make([]byte, 16)
	randBytes(b[:])
	return base64EncWithoutPadding(b)
}

// Generate a random 14 bit integer
func generateRegistrationID() uint32 {
	return randUint32() & 0x3fff
}

// Generate a 256 bit AES and a 160 bit HMAC-SHA1 key
// to be used to secure the communication with the server
func generateSignalingKey() []byte {
	b := make([]byte, 52)
	randBytes(b[:])
	return b
}

// Base64-encodes without padding the result
func base64EncWithoutPadding(b []byte) string {
	s := base64.StdEncoding.EncodeToString(b)
	return strings.TrimRight(s, "=")
}

// Base64-decodes a non-padded string
func base64DecodeNonPadded(s string) ([]byte, error) {
	if len(s)%4 != 0 {
		s = s + strings.Repeat("=", 4-len(s)%4)
	}
	return base64.StdEncoding.DecodeString(s)
}

func encodeKey(key []byte) string {
	return base64EncWithoutPadding(append([]byte{5}, key[:]...))
}

func decodeKey(s string) ([]byte, error) {
	b, err := base64DecodeNonPadded(s)
	if err != nil {
		return nil, err
	}
	if len(b) != 33 || b[0] != 5 {
		return nil, errors.New("Public key not formatted correctly")
	}
	return b[1:], nil
}

func decodeSignature(s string) ([]byte, error) {
	b, err := base64DecodeNonPadded(s)
	if err != nil {
		return nil, err
	}
	if len(b) != 64 {
		return nil, errors.New("Signature not 64 bytes")
	}
	return b, nil
}

func needsRegistration() bool {
	return !textSecureStore.valid()
}

var identityKey *axolotl.IdentityKeyPair

type outgoingMessage struct {
	tel        string
	msg        string
	group      *groupMessage
	attachment *att
	flags      uint32
}

// SendMessage sends the given text message to the given contact.
func SendMessage(tel, msg string) error {
	omsg := &outgoingMessage{
		tel: tel,
		msg: msg,
	}
	err := sendMessage(omsg)
	if err != nil {
		return err
	}
	return nil
}

// SendFileAttachment sends the contents of a file, associated
// with an optional message to a given contact.
func SendFileAttachment(tel, msg string, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}

	ct := mime.TypeByExtension(filepath.Ext(path))
	a, err := uploadAttachment(f, ct)
	if err != nil {
		return err
	}
	omsg := &outgoingMessage{
		tel:        tel,
		msg:        msg,
		attachment: a,
	}
	err = sendMessage(omsg)
	if err != nil {
		return err
	}
	return nil
}

// EndSession terminates the session with the given peer.
func EndSession(tel string) error {
	omsg := &outgoingMessage{
		tel:   tel,
		msg:   "TERMINATE",
		flags: uint32(textsecure.DataMessage_END_SESSION),
	}
	err := sendMessage(omsg)
	if err != nil {
		return err
	}
	textSecureStore.DeleteAllSessions(recID(tel))
	return nil
}

// Message represents a message received from the peer.
// It can optionally include attachments and be sent to a group.
type Message struct {
	source      string
	message     string
	attachments [][]byte
	group       string
	timestamp   uint64
}

// Source returns the ID of the sender of the message.
func (m *Message) Source() string {
	return m.source
}

// Message returns the message body.
func (m *Message) Message() string {
	return m.message
}

// Attachments returns the list of attachments on the message.
func (m *Message) Attachments() [][]byte {
	return m.attachments
}

// Group returns the group name or empty.
func (m *Message) Group() string {
	return m.group
}

// Timestamp returns the timestamp of the message
func (m *Message) Timestamp() time.Time {
	return time.Unix(int64(m.timestamp/1000), 0)
}

// Client contains application specific data and callbacks.
type Client struct {
	GetPhoneNumber      func() string
	GetVerificationCode func() string
	GetStoragePassword  func() string
	GetConfig           func() (*Config, error)
	GetLocalContacts    func() ([]Contact, error)
	MessageHandler      func(*Message)
	RegistrationDone    func()
}

var (
	config *Config
	client *Client
)

// setupLogging sets the logging verbosity level based on configuration
// and environment variables
func setupLogging() {
	loglevel := config.LogLevel
	if loglevel == "" {
		loglevel = os.Getenv("TEXTSECURE_LOGLEVEL")
	}

	switch strings.ToUpper(loglevel) {
	case "DEBUG":
		log.SetLevel(log.DebugLevel)
	case "INFO":
		log.SetLevel(log.InfoLevel)
	case "WARN":
		log.SetLevel(log.WarnLevel)
	case "ERROR":
		log.SetLevel(log.ErrorLevel)
	default:
		log.SetLevel(log.ErrorLevel)
	}
}

// Setup initializes the package.
func Setup(c *Client) error {
	var err error

	client = c

	config, err = loadConfig()
	if err != nil {
		return err
	}

	setupLogging()
	err = setupStore()
	if err != nil {
		return err
	}

	if needsRegistration() {
		registrationInfo.registrationID = generateRegistrationID()
		textSecureStore.SetLocalRegistrationID(registrationInfo.registrationID)

		registrationInfo.password = generatePassword()
		textSecureStore.storeHTTPPassword(registrationInfo.password)

		registrationInfo.signalingKey = generateSignalingKey()
		textSecureStore.storeHTTPSignalingKey(registrationInfo.signalingKey)

		identityKey = axolotl.GenerateIdentityKeyPair()
		err := textSecureStore.SetIdentityKeyPair(identityKey)
		if err != nil {
			return err
		}

		err = registerDevice()
		if err != nil {
			return err
		}
	}
	registrationInfo.registrationID, err = textSecureStore.GetLocalRegistrationID()
	if err != nil {
		return err
	}
	registrationInfo.password, err = textSecureStore.loadHTTPPassword()
	if err != nil {
		return err
	}
	registrationInfo.signalingKey, err = textSecureStore.loadHTTPSignalingKey()
	if err != nil {
		return err
	}
	setupTransporter()
	identityKey, err = textSecureStore.GetIdentityKeyPair()
	return err
}

func registerDevice() error {
	if config.Tel == "" {
		config.Tel = client.GetPhoneNumber()
	}
	setupTransporter()
	code, err := requestCode(config.Tel, config.VerificationType)
	if err != nil {
		return err
	}
	if config.VerificationType != "dev" {
		code = client.GetVerificationCode()
	}
	err = verifyCode(code)
	if err != nil {
		return err
	}
	err = generatePreKeys()
	if err != nil {
		return err
	}
	err = generatePreKeyState()
	if err != nil {
		return err
	}
	err = registerPreKeys()
	if err != nil {
		return err
	}
	if client.RegistrationDone != nil {
		client.RegistrationDone()
	}
	return nil
}

func handleReceipt(env *textsecure.Envelope) {
	//log.Printf("Receipt %+v\n", env)
}

func recID(source string) string {
	return source[1:]
}

func handleMessage(src string, timestamp uint64, b []byte, legacy bool) error {
	b = stripPadding(b)
	if legacy {
		dm := &textsecure.DataMessage{}
		err := proto.Unmarshal(b, dm)
		if err != nil {
			return err
		}
		return handleDataMessage(src, timestamp, dm)
	} else {
		content := &textsecure.Content{}
		err := proto.Unmarshal(b, content)
		if err != nil {
			return err
		}
		if dm := content.GetDataMessage(); dm != nil {
			return handleDataMessage(src, timestamp, dm)
		}
		return handleSyncMessage(src, timestamp, content.GetSyncMessage())
	}
}

func handleFlags(src string, dm *textsecure.DataMessage) error {
	if dm.GetFlags() == uint32(textsecure.DataMessage_END_SESSION) {
		textSecureStore.DeleteAllSessions(recID(src))
	}
	return nil
}

// handleDataMessage handles an incoming DataMessage and calls client callbacks
func handleDataMessage(src string, timestamp uint64, dm *textsecure.DataMessage) error {
	err := handleFlags(src, dm)
	if err != nil {
		return err
	}

	atts, err := handleAttachments(dm)
	if err != nil {
		return err
	}

	gr, err := handleGroups(src, dm)
	if err != nil {
		return err
	}

	msg := &Message{
		source:      src,
		message:     dm.GetBody(),
		attachments: atts,
		group:       gr,
		timestamp:   timestamp,
	}

	if client.MessageHandler != nil {
		client.MessageHandler(msg)
	}
	return nil
}

func getMessage(env *textsecure.Envelope) ([]byte, bool) {
	if msg := env.GetContent(); msg != nil {
		return msg, false
	}
	return env.GetLegacyMessage(), true
}

// Authenticate and decrypt a received message
func handleReceivedMessage(msg []byte) error {
	macpos := len(msg) - 10
	tmac := msg[macpos:]
	aesKey := registrationInfo.signalingKey[:32]
	macKey := registrationInfo.signalingKey[32:]
	if !axolotl.ValidTruncMAC(msg[:macpos], tmac, macKey) {
		return errors.New("Invalid MAC for Incoming Message")
	}
	ciphertext := msg[1:macpos]

	plaintext, err := axolotl.Decrypt(aesKey, ciphertext)
	if err != nil {
		return err
	}
	env := &textsecure.Envelope{}
	err = proto.Unmarshal(plaintext, env)
	if err != nil {
		return err
	}
	//log.Printf("%s %s %d\n", env.GetType(), env.GetSource(), env.GetSourceDevice())
	recid := recID(env.GetSource())
	sc := axolotl.NewSessionCipher(textSecureStore, textSecureStore, textSecureStore, textSecureStore, recid, env.GetSourceDevice())
	switch *env.Type {
	case textsecure.Envelope_RECEIPT:
		handleReceipt(env)
		return nil
	case textsecure.Envelope_CIPHERTEXT:
		msg, legacy := getMessage(env)
		wm, err := axolotl.LoadWhisperMessage(msg)
		if err != nil {
			return err
		}
		b, err := sc.SessionDecryptWhisperMessage(wm)
		if err != nil {
			return err
		}
		err = handleMessage(env.GetSource(), env.GetTimestamp(), b, legacy)
		if err != nil {
			return err
		}

	case textsecure.Envelope_PREKEY_BUNDLE:
		msg, legacy := getMessage(env)
		pkwm, err := axolotl.LoadPreKeyWhisperMessage(msg)
		if err != nil {
			return err
		}
		b, err := sc.SessionDecryptPreKeyWhisperMessage(pkwm)
		if err != nil {
			return err
		}
		err = handleMessage(env.GetSource(), env.GetTimestamp(), b, legacy)
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("Not implemented %d", *env.Type)
	}

	return nil
}
