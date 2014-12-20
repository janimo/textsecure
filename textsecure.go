// Copyright (c) 2014 Canonical Ltd.
// Licensed under the GPLv3, see the COPYING file for details.

package textsecure

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"path/filepath"
	"runtime/debug"
	"strings"
	"github.com/golang/protobuf/proto"

	"github.com/janimo/textsecure/axolotl"
	"github.com/janimo/textsecure/protobuf"
)

var (
	storageDir string
	configDir  string
	configFile string
)

// Generate a random 16 byte string used for HTTP Basic Authentication to the server
func generatePassword() string {
	b := make([]byte, 16)
	randBytes(b[:])
	return base64EncWithoutPadding(b)
}

// Generate a random 14 bit integer
func generateRegistrationId() uint32 {
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
func base64DecodeNonPadded(s string) []byte {
	if len(s)%4 != 0 {
		s = s + strings.Repeat("=", 4-len(s)%4)
	}
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		log.Fatal(err)
	}
	return b
}

func encodeKey(key [32]byte) string {
	return base64EncWithoutPadding(append([]byte{5}, key[:]...))
}

func decodeKey(s string) []byte {
	b := base64DecodeNonPadded(s)
	if len(b) != 33 || b[0] != 5 {
		log.Fatal("Public key not formatted correctly")
	}
	return b[1:]
}

func decodeSignature(s string) []byte {
	b := base64DecodeNonPadded(s)
	if len(b) != 64 {
		log.Fatal("Signature not 64 bytes")
	}
	return b
}

var config *Config

func needsRegistration() bool {
	return !textSecureStore.valid()
}

var identityKey *axolotl.IdentityKeyPair

func SendMessage(tel, msg string) {
	err := sendMessage(tel, msg)
	if err != nil {
		log.Fatal(err)
	}
}

func SendAttachment(tel string, msg, path string) {
	a := UploadAttachment(path)
	err := sendAttachment(tel, msg, a)
	if err != nil {
		log.Fatal(err)
	}
}

type Client struct {
	RootDir          string
	ReadLine         func(string) string
	GetConfig        func() *Config
	GetLocalContacts func() ([]Contact, error)
}

var client *Client

func Setup(c *Client) {
	var err error

	client = c

	configDir = filepath.Join(client.RootDir, ".config")
	storageDir = filepath.Join(client.RootDir, ".storage")

	configFile = filepath.Join(configDir, "config.yml")
	config, err = readConfig(configFile)
	if err != nil {
		log.Panic(err)
	}

	//get password from config file (development only!), if empty read it from the command line
	password := config.StoragePassword
	if password == "" {
		password = readLine("Enter store password (empty for unencrypted store):")
	}

	setupStore(password)

	if needsRegistration() {
		registrationInfo.registrationId = generateRegistrationId()
		textSecureStore.SetLocalRegistrationId(registrationInfo.registrationId)

		registrationInfo.password = generatePassword()
		textSecureStore.storeHTTPPassword(registrationInfo.password)

		registrationInfo.signalingKey = generateSignalingKey()
		textSecureStore.storeHTTPSignalingKey(registrationInfo.signalingKey)

		identityKey = axolotl.GenerateIdentityKeyPair()
		textSecureStore.SetIdentityKeyPair(identityKey)

		generatePreKeys()
		loadPreKeys()
		setupTransporter()
		registerDevice()
	}
	registrationInfo.registrationId = textSecureStore.GetLocalRegistrationId()
	registrationInfo.password = textSecureStore.loadHTTPPassword()
	registrationInfo.signalingKey = textSecureStore.loadHTTPSignalingKey()
	setupTransporter()
	loadPreKeys()
	identityKey = textSecureStore.GetIdentityKeyPair()
}

func registerDevice() {
	generatePreKeyState()
	vt := config.VerificationType
	if vt == "" {
		vt = "sms"
	}
	code := requestCode(config.Tel, vt)
	if code == "" {
		code = readLine("Enter verification number (without the '-')>")
	}
	code = strings.Replace(code, "-", "", -1)
	verifyCode(code)
	registerPreKeys2()
	log.Println("Registration done")
}

func handleReceipt(ipms *textsecure.IncomingPushMessageSignal) {
	//log.Printf("Receipt %+v\n", ipms)
}

func recId(source string) string {
	return source[1:]
}

func handleAttachments(pmc *textsecure.PushMessageContent) error {
	atts := pmc.GetAttachments()
	for _, a := range atts {
		loc := getAttachmentLocation(*a.Id)
		resp, err := http.Get(loc)
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		b, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return err
		}

		l := len(b) - 32
		if !verifyMAC(a.Key[32:], b[:l], b[l:]) {
			return errors.New("Invalid MAC on attachment")
		}

		b, err = decryptAttachment(a.Key[:32], b[:l])
		if err != nil {
			return err
		}
	}
	return nil
}

func getMessageBody(b []byte) string {
	b = stripPadding(b)
	pmc := &textsecure.PushMessageContent{}
	err := proto.Unmarshal(b, pmc)
	if err != nil {
		log.Println("Unmarshal Push Message Content: ", err)
		return ""
	}
	err = handleAttachments(pmc)
	if err != nil {
		log.Printf("Error getting attachments: %s\n", err)
	}

	return pmc.GetBody()
}

// Authenticate and decrypt a received message
func handleReceivedMessage(msg []byte, f func(string, string)) error {
	defer func() {
		if err := recover(); err != nil {
			log.Printf("PANIC: %s\n", err)
			log.Printf("%s\n", debug.Stack())
		}
	}()

	macpos := len(msg) - 10
	tmac := msg[macpos:]
	aesKey := registrationInfo.signalingKey[:32]
	macKey := registrationInfo.signalingKey[32:]
	if !axolotl.ValidTruncMAC(msg[:macpos], tmac, macKey) {
		return errors.New("Invalid MAC for Incoming Message")
	}
	ciphertext := msg[1:macpos]

	plaintext := axolotl.Decrypt(aesKey, ciphertext)
	ipms := &textsecure.IncomingPushMessageSignal{}
	err := proto.Unmarshal(plaintext, ipms)
	if err != nil {
		return err
	}
	//log.Printf("%s %s %d\n", ipms.GetType(), ipms.GetSource(), ipms.GetSourceDevice())
	recid := recId(ipms.GetSource())
	sc := axolotl.NewSessionCipher(textSecureStore, textSecureStore, textSecureStore, textSecureStore, recid, ipms.GetSourceDevice())
	switch *ipms.Type {
	case textsecure.IncomingPushMessageSignal_RECEIPT:
		handleReceipt(ipms)
		return nil
	case textsecure.IncomingPushMessageSignal_CIPHERTEXT:
		wm, err := axolotl.LoadWhisperMessage(ipms.GetMessage())
		if err != nil {
			return err
		}
		b, err := sc.SessionDecryptWhisperMessage(wm)
		if err != nil {
			return err
		}
		f(ipms.GetSource(), getMessageBody(b))
	case textsecure.IncomingPushMessageSignal_PLAINTEXT:
		pmc := &textsecure.PushMessageContent{}
		err = proto.Unmarshal(ipms.GetMessage(), pmc)
		if err != nil {
			return err
		}
	case textsecure.IncomingPushMessageSignal_PREKEY_BUNDLE:
		pkwm, err := axolotl.LoadPreKeyWhisperMessage(ipms.GetMessage())
		if err != nil {
			return err
		}
		b, err := sc.SessionDecryptPreKeyWhisperMessage(pkwm)
		if err != nil {
			return err
		}
		f(ipms.GetSource(), getMessageBody(b))
	default:
		return fmt.Errorf("Not implemented", *ipms.Type)
	}

	return nil
}
