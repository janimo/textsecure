// Copyright (c) 2014 Canonical Ltd.
// Licensed under the GPLv3, see the COPYING file for details.

package axolotl

// PreKey and SignedPreKey support

import (
	"errors"

	"github.com/golang/protobuf/proto"
	protobuf "github.com/janimo/textsecure/axolotl/protobuf"
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
func LoadPreKeyRecord(serialized []byte) (*PreKeyRecord, error) {
	record := &PreKeyRecord{Pkrs: &protobuf.PreKeyRecordStructure{}}
	err := proto.Unmarshal(serialized, record.Pkrs)
	if err != nil {
		return nil, err
	}
	return record, nil
}

// Serialize marshals the prekey into a protobuf.
func (record *PreKeyRecord) Serialize() ([]byte, error) {
	b, err := proto.Marshal(record.Pkrs)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func (record *PreKeyRecord) getKeyPair() *ECKeyPair {
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

// Serialize marshals the signed prekey into a protobuf.
func (record *SignedPreKeyRecord) Serialize() ([]byte, error) {
	b, err := proto.Marshal(record.Spkrs)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func (record *SignedPreKeyRecord) getKeyPair() *ECKeyPair {
	return MakeECKeyPair(record.Spkrs.GetPrivateKey(), record.Spkrs.GetPublicKey())
}

// PreKeyBundle contains the data required to initialize a sender session.
// It is constructed from PreKeys registered by the peer.
type PreKeyBundle struct {
	RegistrationID uint32
	DeviceID       uint32

	PreKeyID     uint32
	PreKeyPublic *ECPublicKey

	SignedPreKeyID        int32
	SignedPreKeyPublic    *ECPublicKey
	SignedPreKeySignature [64]byte

	IdentityKey *IdentityKey
}

// NewPreKeyBundle creates a PreKeyBundle structure with the given fields.
func NewPreKeyBundle(registrationID, deviceID, preKeyID uint32, preKey *ECPublicKey,
	signedPreKeyID int32, signedPreKey *ECPublicKey, signature []byte,
	identityKey *IdentityKey) (*PreKeyBundle, error) {
	pkb := &PreKeyBundle{
		RegistrationID:     registrationID,
		DeviceID:           deviceID,
		PreKeyID:           preKeyID,
		PreKeyPublic:       preKey,
		SignedPreKeyID:     signedPreKeyID,
		SignedPreKeyPublic: signedPreKey,
		IdentityKey:        identityKey,
	}
	if len(signature) != 64 {
		return nil, errors.New("Signature length is not 64")
	}
	copy(pkb.SignedPreKeySignature[:], signature)
	return pkb, nil
}
