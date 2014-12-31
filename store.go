// Copyright (c) 2014 Canonical Ltd.
// Licensed under the GPLv3, see the COPYING file for details.

package textsecure

import (
	"bytes"
	"crypto/sha1"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/janimo/textsecure/axolotl"
	"golang.org/x/crypto/pbkdf2"
)

//FIXME: too manic panic calls, bubble up errors

// TextSecureStore implements the PreKeyStore, SignedPreKeyStore,
// IdentityStore and SessionStore interfaces from the axolotl package
// Blobs are encrypted with AES-128 and authenticated with HMAC-SHA1
type TextSecureStore struct {
	preKeysDir       string
	signedPreKeysDir string
	identityDir      string
	sessionsDir      string

	insecure bool //If the user-supplied password is empty, the store is unencrypted
	aesKey   []byte
	macKey   []byte
}

func NewTextSecureStore(password, path string) (*TextSecureStore, error) {
	ts := &TextSecureStore{
		preKeysDir:       filepath.Join(path, "prekeys"),
		signedPreKeysDir: filepath.Join(path, "signed_prekeys"),
		identityDir:      filepath.Join(path, "identity"),
		sessionsDir:      filepath.Join(path, "sessions"),
		insecure:         password == "",
	}

	// Create dirs in case this is first run
	os.MkdirAll(ts.preKeysDir, 0700)
	os.MkdirAll(ts.signedPreKeysDir, 0700)
	os.MkdirAll(ts.identityDir, 0700)
	os.MkdirAll(ts.sessionsDir, 0700)

	// If there is a password, generate the keys from it
	if !ts.insecure {
		salt := make([]byte, 8)
		saltFile := filepath.Join(path, "salt")

		var err error

		// Create salt if this is first run
		if !exists(saltFile) {
			randBytes(salt)
			err = ioutil.WriteFile(saltFile, salt, 0600)
			if err != nil {
				return nil, err
			}
		} else {
			salt, err = ioutil.ReadFile(saltFile)
			if err != nil {
				return nil, err
			}
		}

		ts.genKeys(password, salt, 1024)
	}

	return ts, nil
}

// Helpers

func idToFilename(id uint32) string {
	return fmt.Sprintf("%09d", id)
}

func filenameToId(fname string) uint32 {
	var id uint32
	_, err := fmt.Sscanf(fname, "%d", &id)
	if err != nil {
		panic(err)
	}
	return uint32(id)
}

func (s *TextSecureStore) readNumFromFile(path string) uint32 {
	b, err := s.readFile(path)
	if err != nil {
		panic(err)
	}
	num, err := strconv.Atoi(string(b))
	if err != nil {
		panic(err)
	}
	return uint32(num)
}

func (s *TextSecureStore) writeNumToFile(path string, num uint32) {
	b := []byte(strconv.Itoa(int(num)))
	s.writeFile(path, b)
}

func (s *TextSecureStore) genKeys(password string, salt []byte, count int) {
	keys := pbkdf2.Key([]byte(password), salt, count, 16+20, sha1.New)
	s.aesKey = keys[:16]
	s.macKey = keys[16:]
}

func (s *TextSecureStore) encrypt(plaintext []byte) ([]byte, error) {
	if s.insecure {
		return plaintext, nil
	}

	return aesEncrypt(s.aesKey, plaintext)
}

func (s *TextSecureStore) decrypt(ciphertext []byte) ([]byte, error) {
	if s.insecure {
		return ciphertext, nil
	}
	return aesDecrypt(s.aesKey, ciphertext)
}

func (s *TextSecureStore) readFile(path string) ([]byte, error) {
	b, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	b, err = s.decrypt(b)
	return b, err
}

func (s *TextSecureStore) writeFile(path string, b []byte) error {
	b, err := s.encrypt(b)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(path, b, 0600)
}

// Identity store

func (s *TextSecureStore) GetLocalRegistrationId() uint32 {
	regidfile := filepath.Join(s.identityDir, "regid")
	return s.readNumFromFile(regidfile)
}

func (s *TextSecureStore) SetLocalRegistrationId(id uint32) {
	regidfile := filepath.Join(s.identityDir, "regid")
	s.writeNumToFile(regidfile, id)
}

func (s *TextSecureStore) GetIdentityKeyPair() *axolotl.IdentityKeyPair {
	idkeyfile := filepath.Join(s.identityDir, "identity_key")
	b, err := s.readFile(idkeyfile)
	if err != nil || len(b) != 64 {
		panic(err)
	}
	return axolotl.NewIdentityKeyPairFromKeys(b[32:], b[:32])
}

func (s *TextSecureStore) GetUserIdentityKeyPair(id string) *axolotl.IdentityKeyPair {
	idkeyfile := filepath.Join(s.identityDir, "remote_"+id)
	if !exists(idkeyfile) {
		panic("id key not found")
	}
	b, err := s.readFile(idkeyfile)
	if err != nil {
		panic(err)
	}
	return axolotl.NewIdentityKeyPairFromKeys(b[32:], b[:32])
}

func (s *TextSecureStore) SetIdentityKeyPair(ikp *axolotl.IdentityKeyPair) {
	idkeyfile := filepath.Join(s.identityDir, "identity_key")
	b := make([]byte, 64)
	copy(b, ikp.PublicKey.Key()[:])
	copy(b[32:], ikp.PrivateKey.Key()[:])
	err := s.writeFile(idkeyfile, b)
	if err != nil {
		panic(err)
	}
}

func (s *TextSecureStore) SaveIdentity(id string, key *axolotl.IdentityKey) {
	idkeyfile := filepath.Join(s.identityDir, "remote_"+id)
	err := s.writeFile(idkeyfile, key.Key()[:])
	if err != nil {
		panic(err)
	}
}

func (s *TextSecureStore) IsTrustedIdentity(id string, key *axolotl.IdentityKey) bool {
	idkeyfile := filepath.Join(s.identityDir, "remote_"+id)
	// Trust on first use (TOFU)
	if !exists(idkeyfile) {
		return true
	}
	b, err := s.readFile(idkeyfile)
	if err != nil {
		return false
	}
	return bytes.Equal(b, key.Key()[:])
}

// Prekey and signed prekey store

func (s *TextSecureStore) preKeysFilePath(id uint32) string {
	return filepath.Join(s.preKeysDir, idToFilename(id))
}

func (s *TextSecureStore) signedPreKeysFilePath(id uint32) string {
	return filepath.Join(s.signedPreKeysDir, idToFilename(id))
}

func (s *TextSecureStore) LoadPreKey(id uint32) (*axolotl.PreKeyRecord, error) {
	b, err := s.readFile(s.preKeysFilePath(id))
	if err != nil {
		return nil, err
	}

	record := axolotl.LoadPreKeyRecord(b)

	return record, nil
}

func (s *TextSecureStore) LoadSignedPreKey(id uint32) (*axolotl.SignedPreKeyRecord, error) {
	b, err := s.readFile(s.signedPreKeysFilePath(id))
	if err != nil {
		return nil, err
	}

	record, err := axolotl.LoadSignedPreKeyRecord(b)
	if err != nil {
		return nil, err
	}

	return record, nil
}

func (s *TextSecureStore) LoadSignedPreKeys() []axolotl.SignedPreKeyRecord {
	keys := []axolotl.SignedPreKeyRecord{}
	//FIXME
	return keys
}

func (s *TextSecureStore) StorePreKey(id uint32, record *axolotl.PreKeyRecord) {
	b := record.Serialize()
	err := s.writeFile(s.preKeysFilePath(id), b)
	if err != nil {
		panic(err)
	}
}

func (s *TextSecureStore) StoreSignedPreKey(id uint32, record *axolotl.SignedPreKeyRecord) {
	b := record.Serialize()
	err := s.writeFile(s.signedPreKeysFilePath(id), b)
	if err != nil {
		panic(err)
	}
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func (s *TextSecureStore) valid() bool {
	return s.ContainsPreKey(lastResortPreKeyId)
}

func (s *TextSecureStore) ContainsPreKey(id uint32) bool {
	return exists(s.preKeysFilePath(id))
}

func (s *TextSecureStore) ContainsSignedPreKey(id uint32) bool {
	return exists(s.signedPreKeysFilePath(id))
}

func (s *TextSecureStore) RemovePreKey(id uint32) {
	_ = os.Remove(s.preKeysFilePath(id))
}

func (s *TextSecureStore) RemoveSignedPreKey(id uint32) {
	_ = os.Remove(s.signedPreKeysFilePath(id))
}

// HTTP API store
func (s *TextSecureStore) storeHTTPPassword(password string) {
	passFile := filepath.Join(s.identityDir, "http_password")
	s.writeFile(passFile, []byte(password))
}

func (s *TextSecureStore) loadHTTPPassword() string {
	passFile := filepath.Join(s.identityDir, "http_password")
	b, err := s.readFile(passFile)
	if err != nil {
		panic(err)
	}
	return string(b)
}

func (s *TextSecureStore) storeHTTPSignalingKey(key []byte) {
	keyFile := filepath.Join(s.identityDir, "http_signaling_key")
	s.writeFile(keyFile, key)
}

func (s *TextSecureStore) loadHTTPSignalingKey() []byte {
	keyFile := filepath.Join(s.identityDir, "http_signaling_key")
	b, err := s.readFile(keyFile)
	if err != nil {
		panic(err)
	}
	return b
}

// Session store

func (s *TextSecureStore) sessionFilePath(recipientId string, deviceId uint32) string {
	return filepath.Join(s.sessionsDir, fmt.Sprintf("%s_%d", recipientId, deviceId))
}

func (s *TextSecureStore) GetSubDeviceSessions(recipientId string) []uint32 {
	sessions := []uint32{}

	filepath.Walk(s.sessionsDir, func(path string, fi os.FileInfo, err error) error {
		if !fi.IsDir() {
			i := strings.LastIndex(path, "_")
			id, _ := strconv.Atoi(path[i+1:])
			sessions[len(sessions)] = uint32(id)
		}
		return nil
	})
	return sessions
}

func (s *TextSecureStore) LoadSession(recipientId string, deviceId uint32) *axolotl.SessionRecord {
	sfile := s.sessionFilePath(recipientId, deviceId)
	b, err := s.readFile(sfile)
	if err != nil {
		return axolotl.NewSessionRecord()
	}
	record := axolotl.LoadSessionRecord(b)

	return record
}

func (s *TextSecureStore) StoreSession(recipientId string, deviceId uint32, record *axolotl.SessionRecord) {
	sfile := s.sessionFilePath(recipientId, deviceId)
	b := record.Serialize()
	err := s.writeFile(sfile, b)
	if err != nil {
		panic(err)
	}
}

func (s *TextSecureStore) ContainsSession(recipientId string, deviceId uint32) bool {
	sfile := s.sessionFilePath(recipientId, deviceId)
	return exists(sfile)
}

func (s *TextSecureStore) DeleteSession(recipientId string, deviceId uint32) {
	sfile := s.sessionFilePath(recipientId, deviceId)
	_ = os.Remove(sfile)
}

func (s *TextSecureStore) DeleteAllSessions(recipientId string) {
	sessions := s.GetSubDeviceSessions(recipientId)
	for _, dev := range sessions {
		_ = os.Remove(s.sessionFilePath(recipientId, dev))
	}
}

var textSecureStore *TextSecureStore

func setupStore(password string) {
	var err error
	textSecureStore, err = NewTextSecureStore(password, storageDir)
	if err != nil {
		panic(err)
	}

}
