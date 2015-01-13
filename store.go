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

var (
	storageDir string
)

// store implements the PreKeyStore, SignedPreKeyStore,
// IdentityStore and SessionStore interfaces from the axolotl package
// Blobs are encrypted with AES-128 and authenticated with HMAC-SHA1
type store struct {
	preKeysDir       string
	signedPreKeysDir string
	identityDir      string
	sessionsDir      string

	unencrypted bool
	aesKey      []byte
	macKey      []byte
}

func newStore(password, path string) (*store, error) {
	ts := &store{
		preKeysDir:       filepath.Join(path, "prekeys"),
		signedPreKeysDir: filepath.Join(path, "signed_prekeys"),
		identityDir:      filepath.Join(path, "identity"),
		sessionsDir:      filepath.Join(path, "sessions"),
		unencrypted:      password == "",
	}

	// Create dirs in case this is first run
	os.MkdirAll(ts.preKeysDir, 0700)
	os.MkdirAll(ts.signedPreKeysDir, 0700)
	os.MkdirAll(ts.identityDir, 0700)
	os.MkdirAll(ts.sessionsDir, 0700)

	// If there is a password, generate the keys from it
	if !ts.unencrypted {
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

func filenameToID(fname string) uint32 {
	var id uint32
	_, err := fmt.Sscanf(fname, "%d", &id)
	if err != nil {
		panic(err)
	}
	return uint32(id)
}

func (s *store) readNumFromFile(path string) uint32 {
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

func (s *store) writeNumToFile(path string, num uint32) {
	b := []byte(strconv.Itoa(int(num)))
	s.writeFile(path, b)
}

func (s *store) genKeys(password string, salt []byte, count int) {
	keys := pbkdf2.Key([]byte(password), salt, count, 16+20, sha1.New)
	s.aesKey = keys[:16]
	s.macKey = keys[16:]
}

func (s *store) encrypt(plaintext []byte) ([]byte, error) {
	if s.unencrypted {
		return plaintext, nil
	}

	return aesEncrypt(s.aesKey, plaintext)
}

func (s *store) decrypt(ciphertext []byte) ([]byte, error) {
	if s.unencrypted {
		return ciphertext, nil
	}
	return aesDecrypt(s.aesKey, ciphertext)
}

func (s *store) readFile(path string) ([]byte, error) {
	b, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	b, err = s.decrypt(b)
	return b, err
}

func (s *store) writeFile(path string, b []byte) error {
	b, err := s.encrypt(b)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(path, b, 0600)
}

// Identity store

func (s *store) GetLocalRegistrationID() uint32 {
	regidfile := filepath.Join(s.identityDir, "regid")
	return s.readNumFromFile(regidfile)
}

func (s *store) SetLocalRegistrationID(id uint32) {
	regidfile := filepath.Join(s.identityDir, "regid")
	s.writeNumToFile(regidfile, id)
}

func (s *store) GetIdentityKeyPair() *axolotl.IdentityKeyPair {
	idkeyfile := filepath.Join(s.identityDir, "identity_key")
	b, err := s.readFile(idkeyfile)
	if err != nil || len(b) != 64 {
		panic(err)
	}
	return axolotl.NewIdentityKeyPairFromKeys(b[32:], b[:32])
}

func (s *store) SetIdentityKeyPair(ikp *axolotl.IdentityKeyPair) {
	idkeyfile := filepath.Join(s.identityDir, "identity_key")
	b := make([]byte, 64)
	copy(b, ikp.PublicKey.Key()[:])
	copy(b[32:], ikp.PrivateKey.Key()[:])
	err := s.writeFile(idkeyfile, b)
	if err != nil {
		panic(err)
	}
}

func (s *store) SaveIdentity(id string, key *axolotl.IdentityKey) {
	idkeyfile := filepath.Join(s.identityDir, "remote_"+id)
	err := s.writeFile(idkeyfile, key.Key()[:])
	if err != nil {
		panic(err)
	}
}

func (s *store) IsTrustedIdentity(id string, key *axolotl.IdentityKey) bool {
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

func (s *store) preKeysFilePath(id uint32) string {
	return filepath.Join(s.preKeysDir, idToFilename(id))
}

func (s *store) signedPreKeysFilePath(id uint32) string {
	return filepath.Join(s.signedPreKeysDir, idToFilename(id))
}

func (s *store) LoadPreKey(id uint32) (*axolotl.PreKeyRecord, error) {
	b, err := s.readFile(s.preKeysFilePath(id))
	if err != nil {
		return nil, err
	}

	record := axolotl.LoadPreKeyRecord(b)

	return record, nil
}

func (s *store) LoadSignedPreKey(id uint32) (*axolotl.SignedPreKeyRecord, error) {
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

func (s *store) LoadSignedPreKeys() []axolotl.SignedPreKeyRecord {
	keys := []axolotl.SignedPreKeyRecord{}
	//FIXME
	return keys
}

func (s *store) StorePreKey(id uint32, record *axolotl.PreKeyRecord) {
	b := record.Serialize()
	err := s.writeFile(s.preKeysFilePath(id), b)
	if err != nil {
		panic(err)
	}
}

func (s *store) StoreSignedPreKey(id uint32, record *axolotl.SignedPreKeyRecord) {
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

func (s *store) valid() bool {
	return s.ContainsPreKey(lastResortPreKeyID)
}

func (s *store) ContainsPreKey(id uint32) bool {
	return exists(s.preKeysFilePath(id))
}

func (s *store) ContainsSignedPreKey(id uint32) bool {
	return exists(s.signedPreKeysFilePath(id))
}

func (s *store) RemovePreKey(id uint32) {
	_ = os.Remove(s.preKeysFilePath(id))
}

func (s *store) RemoveSignedPreKey(id uint32) {
	_ = os.Remove(s.signedPreKeysFilePath(id))
}

// HTTP API store
func (s *store) storeHTTPPassword(password string) {
	passFile := filepath.Join(s.identityDir, "http_password")
	s.writeFile(passFile, []byte(password))
}

func (s *store) loadHTTPPassword() string {
	passFile := filepath.Join(s.identityDir, "http_password")
	b, err := s.readFile(passFile)
	if err != nil {
		panic(err)
	}
	return string(b)
}

func (s *store) storeHTTPSignalingKey(key []byte) {
	keyFile := filepath.Join(s.identityDir, "http_signaling_key")
	s.writeFile(keyFile, key)
}

func (s *store) loadHTTPSignalingKey() []byte {
	keyFile := filepath.Join(s.identityDir, "http_signaling_key")
	b, err := s.readFile(keyFile)
	if err != nil {
		panic(err)
	}
	return b
}

// Session store

func (s *store) sessionFilePath(recipientID string, deviceID uint32) string {
	return filepath.Join(s.sessionsDir, fmt.Sprintf("%s_%d", recipientID, deviceID))
}

func (s *store) GetSubDeviceSessions(recipientID string) []uint32 {
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

func (s *store) LoadSession(recipientID string, deviceID uint32) *axolotl.SessionRecord {
	sfile := s.sessionFilePath(recipientID, deviceID)
	b, err := s.readFile(sfile)
	if err != nil {
		return axolotl.NewSessionRecord()
	}
	record := axolotl.LoadSessionRecord(b)

	return record
}

func (s *store) StoreSession(recipientID string, deviceID uint32, record *axolotl.SessionRecord) {
	sfile := s.sessionFilePath(recipientID, deviceID)
	b := record.Serialize()
	err := s.writeFile(sfile, b)
	if err != nil {
		panic(err)
	}
}

func (s *store) ContainsSession(recipientID string, deviceID uint32) bool {
	sfile := s.sessionFilePath(recipientID, deviceID)
	return exists(sfile)
}

func (s *store) DeleteSession(recipientID string, deviceID uint32) {
	sfile := s.sessionFilePath(recipientID, deviceID)
	_ = os.Remove(sfile)
}

func (s *store) DeleteAllSessions(recipientID string) {
	sessions := s.GetSubDeviceSessions(recipientID)
	for _, dev := range sessions {
		_ = os.Remove(s.sessionFilePath(recipientID, dev))
	}
}

var textSecureStore *store

func setupStore() error {
	var err error
	storageDir = filepath.Join(client.RootDir, ".storage")

	password := ""
	if !config.UnencryptedStorage {
		password = config.StoragePassword
		if password == "" {
			if client.GetStoragePassword != nil {
				password = client.GetStoragePassword()
			} else {
				password = readLine("Enter store password (empty for unencrypted storage):")
			}
		}
	}

	textSecureStore, err = newStore(password, storageDir)
	if err != nil {
		return err
	}
	return nil
}
