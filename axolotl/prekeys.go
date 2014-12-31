// Copyright (c) 2014 Canonical Ltd.
// Licensed under the GPLv3, see the COPYING file for details.

package axolotl

// PreKey and SignedPreKey support

import (
	"errors"
	"log"

	"github.com/golang/protobuf/proto"
	protobuf "github.com/zmanian/textsecure/axolotl/protobuf"
)

var maxValue uint32 = 0xFFFFFF

// PreKeyRecord represents a prekey, and is simply wrapper around the corresponding protobuf struct
type PreKeyRecord struct {
	Pkrs *protobuf.PreKeyRecordStructure
}

// NewPreKeyRecord creates a new PreKeyRecord instance
func NewPreKeyRecord(id uint32, kp *ECKeyPair) *PreKeyRecord {
	pkr := &PreKeyRecord{
		&protobuf.PreKeyRecordStructure{
			Id:         &id,
			PublicKey:  kp.PublicKey.Key()[:],
			PrivateKey: kp.PrivateKey.Key()[:],
		},
	}
	return pkr
}

// LoadPreKeyRecord creates a PreKeyRecord instance from a serialized bytestream
func LoadPreKeyRecord(serialized []byte) *PreKeyRecord {
	record := &PreKeyRecord{Pkrs: &protobuf.PreKeyRecordStructure{}}
	err := proto.Unmarshal(serialized, record.Pkrs)
	if err != nil {
		log.Fatal("Cannot unmarshal PreKeyRecord", err)
	}
	return record
}

func (record *PreKeyRecord) Serialize() []byte {
	b, err := proto.Marshal(record.Pkrs)
	if err != nil {
		log.Fatal("Cannot marshal PreKeyRecord", err)
	}
	return b
}

func (record *PreKeyRecord) GetKeyPair() *ECKeyPair {
	return MakeECKeyPair(record.Pkrs.GetPrivateKey(), record.Pkrs.GetPublicKey())
}

// GenerateLastResortPreKey creates the last resort PreKey.
// Clients should do this only once, at install time, and durably store it for
// the length of the install.
func GenerateLastResortPreKey() *PreKeyRecord {
	return NewPreKeyRecord(maxValue, NewECKeyPair())
}

// GeneratePreKeys creates a list of PreKeys.
// Clients should do this at install time, and subsequently any time the list
// of PreKeys stored on the server runs low.
func GeneratePreKeys(start, count int) []*PreKeyRecord {
	records := make([]*PreKeyRecord, count)
	for i := 0; i < count; i++ {
		records[i] = NewPreKeyRecord(uint32(start+i), NewECKeyPair())
	}
	return records
}

// SignedPreKeyRecord represents a prekey, and is simply wrapper around the corresponding protobuf struct
type SignedPreKeyRecord struct {
	Spkrs *protobuf.SignedPreKeyRecordStructure
}

// NewSignedPreKeyRecord creates a new SignedPreKeyRecord instance
func NewSignedPreKeyRecord(id uint32, timestamp uint64, kp *ECKeyPair, signature []byte) *SignedPreKeyRecord {
	return &SignedPreKeyRecord{
		&protobuf.SignedPreKeyRecordStructure{
			Id:         &id,
			PublicKey:  kp.PublicKey.Key()[:],
			PrivateKey: kp.PrivateKey.Key()[:],
			Timestamp:  &timestamp,
			Signature:  signature,
		},
	}
}

// LoadSignedPreKeyRecord creates a SignedPreKeyRecord instance from a serialized bytestream
func LoadSignedPreKeyRecord(serialized []byte) (*SignedPreKeyRecord, error) {
	record := &SignedPreKeyRecord{Spkrs: &protobuf.SignedPreKeyRecordStructure{}}
	err := proto.Unmarshal(serialized, record.Spkrs)
	if err != nil {
		return nil, err
	}
	return record, nil
}

func (record *SignedPreKeyRecord) Serialize() []byte {
	b, err := proto.Marshal(record.Spkrs)
	if err != nil {
		log.Fatal("Cannot marshal SignedPreKeyRecord", err)
	}
	return b
}

func (record *SignedPreKeyRecord) GetKeyPair() *ECKeyPair {
	return MakeECKeyPair(record.Spkrs.GetPrivateKey(), record.Spkrs.GetPublicKey())
}

var InvalidKeyIdError = errors.New("Invalid PreKey ID")

type PreKeyBundle struct {
	RegistrationId uint32
	DeviceId       uint32

	PreKeyId     uint32
	PreKeyPublic *ECPublicKey

	SignedPreKeyId        int32
	SignedPreKeyPublic    *ECPublicKey
	SignedPreKeySignature [64]byte

	IdentityKey *IdentityKey
}

func NewPreKeyBundle(registrationId, deviceId, preKeyId uint32, preKey *ECPublicKey,
	signedPreKeyId int32, signedPreKey *ECPublicKey, signature []byte,
	identityKey *IdentityKey) (*PreKeyBundle, error) {
	pkb := &PreKeyBundle{
		RegistrationId:     registrationId,
		DeviceId:           deviceId,
		PreKeyId:           preKeyId,
		PreKeyPublic:       preKey,
		SignedPreKeyId:     signedPreKeyId,
		SignedPreKeyPublic: signedPreKey,
		IdentityKey:        identityKey,
	}
	if len(signature) != 64 {
		return nil, errors.New("Signature length is not 64")
	}
	copy(pkb.SignedPreKeySignature[:], signature)
	return pkb, nil
}
