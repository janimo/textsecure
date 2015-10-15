// Copyright (c) 2014 Canonical Ltd.
// Licensed under the GPLv3, see the COPYING file for details.

// Package textsecure implements the TextSecure client protocol.
package textsecure

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/golang/protobuf/proto"
	"github.com/janimo/textsecure/vendor/magic"

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

// ErrBadPublicKey is raised when a given public key is not in the
// expected format.
var ErrBadPublicKey = errors.New("public key not formatted correctly")

func decodeKey(s string) ([]byte, error) {
	b, err := base64DecodeNonPadded(s)
	if err != nil {
		return nil, err
	}
	if len(b) != 33 || b[0] != 5 {
		return nil, ErrBadPublicKey
	}
	return b[1:], nil
}

func decodeSignature(s string) ([]byte, error) {
	b, err := base64DecodeNonPadded(s)
	if err != nil {
		return nil, err
	}
	if len(b) != 64 {
		return nil, fmt.Errorf("signature is %d, not 64 bytes", len(b))
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
func SendMessage(tel, msg string) (uint64, error) {
	omsg := &outgoingMessage{
		tel: tel,
		msg: msg,
	}
	return sendMessage(omsg)
}

// SendAttachment sends the contents of a reader, along
// with an optional message to a given contact.
func SendAttachment(tel, msg string, r io.Reader) (uint64, error) {
	ct, r := magic.MIMETypeFromReader(r)
	a, err := uploadAttachment(r, ct)
	if err != nil {
		return 0, err
	}
	omsg := &outgoingMessage{
		tel:        tel,
		msg:        msg,
		attachment: a,
	}
	return sendMessage(omsg)
}

// EndSession terminates the session with the given peer.
func EndSession(tel string, msg string) (uint64, error) {
	omsg := &outgoingMessage{
		tel:   tel,
		msg:   msg,
		flags: uint32(textsecure.DataMessage_END_SESSION),
	}
	ts, err := sendMessage(omsg)
	if err != nil {
		return 0, err
	}
	textSecureStore.DeleteAllSessions(recID(tel))
	return ts, nil
}

// Message represents a message received from the peer.
// It can optionally include attachments and be sent to a group.
type Message struct {
	source      string
	message     string
	attachments []io.Reader
	group       *Group
	timestamp   uint64
	flags       uint32
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
func (m *Message) Attachments() []io.Reader {
	return m.attachments
}

// Group returns group information.
func (m *Message) Group() *Group {
	return m.group
}

// Timestamp returns the timestamp of the message
func (m *Message) Timestamp() uint64 {
	return m.timestamp
}

// Flags returns the flags in the message
func (m *Message) Flags() uint32 {
	return m.flags
}

// Client contains application specific data and callbacks.
type Client struct {
	GetPhoneNumber      func() string
	GetVerificationCode func() string
	GetStoragePassword  func() string
	GetConfig           func() (*Config, error)
	GetLocalContacts    func() ([]Contact, error)
	MessageHandler      func(*Message)
	ReceiptHandler      func(string, uint32, uint64)
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
	if client.ReceiptHandler != nil {
		client.ReceiptHandler(env.GetSource(), env.GetSourceDevice(), env.GetTimestamp())
	}
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
	}

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

var EndSessionFlag uint32 = 1

func handleFlags(src string, dm *textsecure.DataMessage) (uint32, error) {
	flags := uint32(0)
	if dm.GetFlags() == uint32(textsecure.DataMessage_END_SESSION) {
		flags = EndSessionFlag
		textSecureStore.DeleteAllSessions(recID(src))
	}
	return flags, nil
}

// handleDataMessage handles an incoming DataMessage and calls client callbacks
func handleDataMessage(src string, timestamp uint64, dm *textsecure.DataMessage) error {
	flags, err := handleFlags(src, dm)
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
		flags:       flags,
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

// MessageTypeNotImplementedError is raised in the unlikely event that an unhandled protocol message type is received.
type MessageTypeNotImplementedError struct {
	typ uint32
}

func (err MessageTypeNotImplementedError) Error() string {
	return fmt.Sprintf("not implemented message type %d", err.typ)
}

// ErrInvalidMACForMessage signals an incoming message with invalid MAC.
var ErrInvalidMACForMessage = errors.New("invalid MAC for incoming message")

// Authenticate and decrypt a received message
func handleReceivedMessage(msg []byte) error {
	macpos := len(msg) - 10
	tmac := msg[macpos:]
	aesKey := registrationInfo.signalingKey[:32]
	macKey := registrationInfo.signalingKey[32:]
	if !axolotl.ValidTruncMAC(msg[:macpos], tmac, macKey) {
		return ErrInvalidMACForMessage
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
		if _, ok := err.(axolotl.DuplicateMessageError); ok {
			log.Infof("Incoming WhisperMessage %s. Ignoring.\n", err)
			return nil
		}
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
		if _, ok := err.(axolotl.DuplicateMessageError); ok {
			log.Infof("Incoming PreKeyWhisperMessage %s. Ignoring.\n", err)
			return nil
		}
		if _, ok := err.(axolotl.PreKeyNotFoundError); ok {
			log.Infof("Incoming PreKeyWhisperMessage %s. Ignoring.\n", err)
			return nil
		}
		if _, ok := err.(axolotl.InvalidMessageError); ok {
			log.Infof("Incoming PreKeyWhisperMessage %s. Ignoring.\n", err)
			return nil
		}
		if err != nil {
			return err
		}
		err = handleMessage(env.GetSource(), env.GetTimestamp(), b, legacy)
		if err != nil {
			return err
		}
	default:
		return MessageTypeNotImplementedError{uint32(*env.Type)}
	}

	return nil
}
