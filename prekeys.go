// Copyright (c) 2014 Canonical Ltd.
// Licensed under the GPLv3, see the COPYING file for details.

package textsecure

import (
	"os"
	"path/filepath"
	"time"

	"github.com/zmanian/textsecure/axolotl"
	"github.com/zmanian/textsecure/curve25519sign"
)

type PreKeyEntity struct {
	Id        uint32 `json:"keyId"`
	PublicKey string `json:"publicKey"`
}

type SignedPreKeyEntity struct {
	Id        uint32 `json:"keyId"`
	PublicKey string `json:"publicKey"`
	Signature string `json:"signature"`
}

type PreKeyState struct {
	IdentityKey   string              `json:"identityKey"`
	PreKeys       []*PreKeyEntity     `json:"preKeys"`
	LastResortKey *PreKeyEntity       `json:"lastResortKey"`
	SignedPreKey  *SignedPreKeyEntity `json:"signedPreKey"`
}

type PreKeyResponseItem struct {
	DeviceID       uint32              `json:"deviceId"`
	RegistrationId uint32              `json:"registrationId"`
	SignedPreKey   *SignedPreKeyEntity `json:"signedPreKey"`
	PreKey         *PreKeyEntity       `json:"preKey"`
}

type PreKeyResponse struct {
	IdentityKey string               `json:"identityKey"`
	Devices     []PreKeyResponseItem `json:"devices"`
}

var preKeys *PreKeyState

func randId() uint32 {
	return randUint32() & 0xffffff
}

func generatePreKeyEntity(record *axolotl.PreKeyRecord) *PreKeyEntity {
	entity := &PreKeyEntity{}
	entity.Id = *record.Pkrs.Id
	entity.PublicKey = base64EncWithoutPadding(append([]byte{5}, record.Pkrs.PublicKey[:]...))
	return entity
}

func generateSignedPreKeyEntity(record *axolotl.SignedPreKeyRecord) *SignedPreKeyEntity {
	entity := &SignedPreKeyEntity{}
	entity.Id = *record.Spkrs.Id
	entity.PublicKey = base64EncWithoutPadding(append([]byte{5}, record.Spkrs.PublicKey[:]...))
	entity.Signature = base64EncWithoutPadding(record.Spkrs.Signature)
	return entity
}

var preKeyRecords []*axolotl.PreKeyRecord

func generatePreKey(id uint32) *axolotl.PreKeyRecord {
	kp := axolotl.NewECKeyPair()
	record := axolotl.NewPreKeyRecord(id, kp)
	textSecureStore.StorePreKey(id, record)
	return record
}

var signedKey *axolotl.SignedPreKeyRecord

var lastResortPreKeyId uint32 = 0xFFFFFF

var preKeyBatchSize = 100

func getNextPreKeyId() uint32 {
	return randId()
}

func generatePreKeys() {
	os.MkdirAll(textSecureStore.preKeysDir, 0700)

	startId := getNextPreKeyId()
	for i := 0; i < preKeyBatchSize; i++ {
		generatePreKey(startId + uint32(i))
	}
	generatePreKey(lastResortPreKeyId)
	signedKey = generateSignedPreKey()
}

func getNextSignedPreKeyId() uint32 {
	return randId()
}

func generateSignedPreKey() *axolotl.SignedPreKeyRecord {
	kp := axolotl.NewECKeyPair()
	id := getNextSignedPreKeyId()
	var random [64]byte
	randBytes(random[:])
	priv := identityKey.PrivateKey.Key()
	signature := curve25519sign.Sign(priv, kp.PublicKey.Serialize(), random)
	record := axolotl.NewSignedPreKeyRecord(id, uint64(time.Now().UnixNano()*1000), kp, signature[:])
	textSecureStore.StoreSignedPreKey(id, record)
	return record
}

func generatePreKeyState() {
	preKeys = &PreKeyState{}
	npkr := len(preKeyRecords)
	preKeys.PreKeys = make([]*PreKeyEntity, npkr-1)
	for i, _ := range preKeys.PreKeys {
		preKeys.PreKeys[i] = generatePreKeyEntity(preKeyRecords[i])
	}
	preKeys.LastResortKey = generatePreKeyEntity(preKeyRecords[npkr-1])
	preKeys.IdentityKey = base64EncWithoutPadding(identityKey.PublicKey.Serialize())
	preKeys.SignedPreKey = generateSignedPreKeyEntity(signedKey)

}

func loadPreKeys() {
	preKeyRecords = []*axolotl.PreKeyRecord{}
	count := 0
	filepath.Walk(textSecureStore.preKeysDir, func(path string, fi os.FileInfo, err error) error {
		if !fi.IsDir() {
			preKeyRecords = append(preKeyRecords, &axolotl.PreKeyRecord{}) //FIXME
			_, fname := filepath.Split(path)
			id := filenameToId(fname)
			preKeyRecords[count], _ = textSecureStore.LoadPreKey(uint32(id))
			count++
		}
		return nil

	})
}
