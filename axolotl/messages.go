// Copyright (c) 2014 Canonical Ltd.
// Licensed under the GPLv3, see the COPYING file for details.

package axolotl

import (
	"crypto/hmac"
	"errors"
	"fmt"

	protobuf "github.com/zmanian/textsecure/axolotl/protobuf"

	"github.com/golang/protobuf/proto"
)

type WhisperMessage struct {
	Version         byte
	RatchetKey      *ECPublicKey
	Counter         uint32
	PreviousCounter uint32
	Ciphertext      []byte
	serialized      []byte
}

const macLength = 8

const currentVersion = 3

func highBitsToInt(b byte) byte {
	return (b & 0xF0) >> 4
}

func makeVersionByte(hi, lo byte) byte {
	return (hi << 4) | lo
}

func LoadWhisperMessage(serialized []byte) (*WhisperMessage, error) {
	version := highBitsToInt(serialized[0])
	message := serialized[1 : len(serialized)-macLength]

	if version != currentVersion {
		return nil, fmt.Errorf("Unsupported version %d\n", version)
	}
	pwm := &protobuf.WhisperMessage{}
	err := proto.Unmarshal(message, pwm)
	if err != nil {
		return nil, err
	}

	if pwm.GetCiphertext() == nil || pwm.GetRatchetKey() == nil {
		return nil, errors.New("Incomplete WhisperMessage")
	}

	wm := &WhisperMessage{
		Version:         version,
		Counter:         pwm.GetCounter(),
		PreviousCounter: pwm.GetPreviousCounter(),
		RatchetKey:      NewECPublicKey(pwm.GetRatchetKey()[1:]),
		Ciphertext:      pwm.GetCiphertext(),
		serialized:      serialized,
	}

	return wm, nil
}

func NewWhisperMessage(messageVersion byte, macKey []byte, ratchetKey *ECPublicKey,
	counter, previousCounter uint32, ciphertext []byte,
	senderIdentity, receiverIdentity *IdentityKey) (*WhisperMessage, error) {

	version := makeVersionByte(messageVersion, currentVersion)

	pwm := &protobuf.WhisperMessage{
		RatchetKey:      ratchetKey.Serialize(),
		Counter:         &counter,
		PreviousCounter: &previousCounter,
		Ciphertext:      ciphertext,
	}

	message, err := proto.Marshal(pwm)
	if err != nil {
		return nil, err
	}

	data := append([]byte{version}, message...)
	mac := getMac(messageVersion, senderIdentity, receiverIdentity, macKey, data)

	wm := &WhisperMessage{
		Version:         messageVersion,
		Counter:         counter,
		PreviousCounter: previousCounter,
		RatchetKey:      ratchetKey,

		Ciphertext: ciphertext,
		serialized: append(data, mac...),
	}

	return wm, nil

}

func getMac(version byte, senderIdentity, receiverIdentity *IdentityKey, macKey, serialized []byte) []byte {
	msg := []byte{}
	if version >= 3 {
		msg = append(msg, senderIdentity.Serialize()...)
		msg = append(msg, receiverIdentity.Serialize()...)
	}
	msg = append(msg, serialized...)
	return ComputeTruncatedMAC(msg, macKey, macLength)
}

func (wm *WhisperMessage) VerifyMAC(senderIdentity, receiverIdentity *IdentityKey, macKey []byte) bool {
	macpos := len(wm.serialized) - macLength

	ourMAC := getMac(wm.Version, senderIdentity, receiverIdentity, macKey, wm.serialized[:macpos])
	theirMAC := wm.serialized[macpos:]
	return hmac.Equal(ourMAC, theirMAC)
}

func (wm *WhisperMessage) Serialize() []byte {
	return wm.serialized
}

type PreKeyWhisperMessage struct {
	Version        byte
	RegistrationId uint32
	PreKeyId       uint32
	SignedPreKeyId uint32
	BaseKey        *ECPublicKey
	IdentityKey    *IdentityKey
	Message        *WhisperMessage
	serialized     []byte
}

func LoadPreKeyWhisperMessage(serialized []byte) (*PreKeyWhisperMessage, error) {
	version := highBitsToInt(serialized[0])

	if version != currentVersion {
		return nil, fmt.Errorf("Unsupported version %d\n", version)
	}

	ppkwm := &protobuf.PreKeyWhisperMessage{}
	err := proto.Unmarshal(serialized[1:len(serialized)], ppkwm)
	if err != nil {
		return nil, err
	}

	if ppkwm.GetBaseKey() == nil ||
		ppkwm.GetIdentityKey() == nil ||
		ppkwm.GetMessage() == nil ||
		ppkwm.GetSignedPreKeyId() == 0 {
		return nil, errors.New("Incomplete PreKeyWhisperMessage")
	}

	wm, err := LoadWhisperMessage(ppkwm.GetMessage())
	if err != nil {
		return nil, err
	}
	pkwm := &PreKeyWhisperMessage{
		Version:        version,
		RegistrationId: ppkwm.GetRegistrationId(),
		PreKeyId:       ppkwm.GetPreKeyId(),
		SignedPreKeyId: ppkwm.GetSignedPreKeyId(),
		BaseKey:        NewECPublicKey(ppkwm.GetBaseKey()[1:]),
		IdentityKey:    NewIdentityKey(ppkwm.GetIdentityKey()[1:]),
		Message:        wm,
		serialized:     serialized,
	}

	return pkwm, nil
}

func NewPreKeyWhisperMessage(messageVersion byte, regid, pkid, spkid uint32, baseKey *ECPublicKey, identityKey *IdentityKey, wm *WhisperMessage) (*PreKeyWhisperMessage, error) {

	ppkwm := &protobuf.PreKeyWhisperMessage{
		RegistrationId: &regid,
		PreKeyId:       &pkid,
		SignedPreKeyId: &spkid,
		BaseKey:        baseKey.Serialize(),
		IdentityKey:    identityKey.Serialize(),
		Message:        wm.Serialize(),
	}

	message, err := proto.Marshal(ppkwm)
	if err != nil {
		return nil, err
	}

	version := makeVersionByte(messageVersion, currentVersion)
	pkwm := &PreKeyWhisperMessage{
		Version:        version,
		RegistrationId: regid,
		PreKeyId:       pkid,
		SignedPreKeyId: spkid,
		BaseKey:        baseKey,
		IdentityKey:    identityKey,
		Message:        wm,
		serialized:     append([]byte{version}, message...),
	}
	return pkwm, nil
}

func (pkwm *PreKeyWhisperMessage) Serialize() []byte {
	return pkwm.serialized
}
