// Copyright (c) 2014 Canonical Ltd.
// Licensed under the GPLv3, see the COPYING file for details.

package textsecure

import (
	"os"
	"path/filepath"
	"time"

	"github.com/janimo/textsecure/axolotl"
	"github.com/janimo/textsecure/curve25519sign"
)

type preKeyEntity struct {
	ID        uint32 `json:"keyId"`
	PublicKey string `json:"publicKey"`
}

type signedPreKeyEntity struct {
	ID        uint32 `json:"keyId"`
	PublicKey string `json:"publicKey"`
	Signature string `json:"signature"`
}

type preKeyState struct {
	IdentityKey   string              `json:"identityKey"`
	PreKeys       []*preKeyEntity     `json:"preKeys"`
	LastResortKey *preKeyEntity       `json:"lastResortKey"`
	SignedPreKey  *signedPreKeyEntity `json:"signedPreKey"`
}

type preKeyResponseItem struct {
	DeviceID       uint32              `json:"deviceId"`
	RegistrationID uint32              `json:"registrationId"`
	SignedPreKey   *signedPreKeyEntity `json:"signedPreKey"`
	PreKey         *preKeyEntity       `json:"preKey"`
}

type preKeyResponse struct {
	IdentityKey string               `json:"identityKey"`
	Devices     []preKeyResponseItem `json:"devices"`
}

var preKeys *preKeyState

func randID() uint32 {
	return randUint32() & 0xffffff
}

func generatepreKeyEntity(record *axolotl.PreKeyRecord) *preKeyEntity {
	entity := &preKeyEntity{}
	entity.ID = *record.Pkrs.Id
	entity.PublicKey = encodeKey(record.Pkrs.PublicKey)
	return entity
}

func generateSignedPreKeyEntity(record *axolotl.SignedPreKeyRecord) *signedPreKeyEntity {
	entity := &signedPreKeyEntity{}
	entity.ID = *record.Spkrs.Id
	entity.PublicKey = encodeKey(record.Spkrs.PublicKey)
	entity.Signature = base64EncWithoutPadding(record.Spkrs.Signature)
	return entity
}

var preKeyRecords []*axolotl.PreKeyRecord

func generatePreKey(id uint32) error {
	kp := axolotl.NewECKeyPair()
	record := axolotl.NewPreKeyRecord(id, kp)
	err := textSecureStore.StorePreKey(id, record)
	return err
}

var signedKey *axolotl.SignedPreKeyRecord

var lastResortPreKeyID uint32 = 0xFFFFFF

var preKeyBatchSize = 100

func getNextPreKeyID() uint32 {
	return randID()
}

func generatePreKeys() error {
	os.MkdirAll(textSecureStore.preKeysDir, 0700)

	startID := getNextPreKeyID()
	for i := 0; i < preKeyBatchSize; i++ {
		err := generatePreKey(startID + uint32(i))
		if err != nil {
			return err
		}
	}
	err := generatePreKey(lastResortPreKeyID)
	if err != nil {
		return err
	}
	signedKey = generateSignedPreKey()
	return nil
}

func getNextSignedPreKeyID() uint32 {
	return randID()
}

func generateSignedPreKey() *axolotl.SignedPreKeyRecord {
	kp := axolotl.NewECKeyPair()
	id := getNextSignedPreKeyID()
	var random [64]byte
	randBytes(random[:])
	priv := identityKey.PrivateKey.Key()
	signature := curve25519sign.Sign(priv, kp.PublicKey.Serialize(), random)
	record := axolotl.NewSignedPreKeyRecord(id, uint64(time.Now().UnixNano()*1000), kp, signature[:])
	textSecureStore.StoreSignedPreKey(id, record)
	return record
}

func generatePreKeyState() error {
	err := loadPreKeys()
	if err != nil {
		return err
	}
	preKeys = &preKeyState{}
	npkr := len(preKeyRecords)
	preKeys.PreKeys = make([]*preKeyEntity, npkr-1)
	for i := range preKeys.PreKeys {
		preKeys.PreKeys[i] = generatepreKeyEntity(preKeyRecords[i])
	}
	preKeys.LastResortKey = generatepreKeyEntity(preKeyRecords[npkr-1])
	preKeys.IdentityKey = base64EncWithoutPadding(identityKey.PublicKey.Serialize())
	preKeys.SignedPreKey = generateSignedPreKeyEntity(signedKey)
	return nil
}

func loadPreKeys() error {
	preKeyRecords = []*axolotl.PreKeyRecord{}
	count := 0
	err := filepath.Walk(textSecureStore.preKeysDir, func(path string, fi os.FileInfo, err error) error {
		if !fi.IsDir() {
			preKeyRecords = append(preKeyRecords, &axolotl.PreKeyRecord{}) //FIXME
			_, fname := filepath.Split(path)
			id, err := filenameToID(fname)
			if err != nil {
				return err
			}
			preKeyRecords[count], _ = textSecureStore.LoadPreKey(uint32(id))
			count++
		}
		return nil

	})
	return err
}
