// Copyright (c) 2014 Canonical Ltd.
// Licensed under the GPLv3, see the COPYING file for details.

package axolotl

import (
	"crypto/hmac"
	"crypto/sha256"
	"io"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

type aliceAxolotlParameters struct {
	OurIdentityKey *IdentityKeyPair
	OurBaseKey     *ECKeyPair

	TheirIdentity      *IdentityKey
	TheirSignedPreKey  *ECPublicKey
	TheirOneTimePreKey *ECPublicKey
	TheirRatchetKey    *ECPublicKey
}

type bobAxolotlParameters struct {
	OurIdentityKey   *IdentityKeyPair
	OurSignedPreKey  *ECKeyPair
	OurOneTimePreKey *ECKeyPair
	OurRatchetKey    *ECKeyPair

	TheirBaseKey  *ECPublicKey
	TheirIdentity *IdentityKey
}

type rootKey struct {
	Key [32]byte
}

func newRootKey(key []byte) *rootKey {
	ensureKeyLength(key)
	rk := &rootKey{}
	copy(rk.Key[:], key)
	return rk
}

func (r *rootKey) createChain(theirRatchetKey *ECPublicKey, ourRatchetKey *ECKeyPair) (*derivedKeys, error) {
	var keyMaterial [32]byte
	calculateAgreement(&keyMaterial, theirRatchetKey.Key(), ourRatchetKey.PrivateKey.Key())
	b, err := DeriveSecrets(keyMaterial[:], r.Key[:], []byte("WhisperRatchet"), 64)
	if err != nil {
		return nil, err
	}
	dk := &derivedKeys{}
	copy(dk.rootKey.Key[:], b[:32])
	copy(dk.chainKey.Key[:], b[32:])
	dk.chainKey.Index = 0
	return dk, nil
}

type chainKey struct {
	Key   [32]byte
	Index uint32
}

func newChainKey(key []byte, index uint32) *chainKey {
	ensureKeyLength(key)
	ck := &chainKey{Index: index}
	copy(ck.Key[:], key)
	return ck
}

type messageKeys struct {
	CipherKey []byte
	MacKey    []byte
	Iv        []byte
	Index     uint32
}

func newMessageKeys(cipherKey, macKey, iv []byte, index uint32) *messageKeys {
	return &messageKeys{
		CipherKey: cipherKey,
		MacKey:    macKey,
		Iv:        iv,
		Index:     index,
	}
}

var (
	messageKeySeed = []byte{1}
	chainKeySeed   = []byte{2}
)

func (c *chainKey) getBaseMaterial(seed []byte) []byte {
	m := hmac.New(sha256.New, c.Key[:])
	m.Write(seed)
	return m.Sum(nil)
}

func (c *chainKey) getNextChainKey() *chainKey {
	b := c.getBaseMaterial(chainKeySeed)
	ck := &chainKey{Index: c.Index + 1}
	copy(ck.Key[:], b)
	return ck
}

func (c *chainKey) getMessageKeys() (*messageKeys, error) {
	b := c.getBaseMaterial(messageKeySeed)
	okm, err := DeriveSecrets(b, nil, []byte("WhisperMessageKeys"), 80)
	if err != nil {
		return nil, err
	}
	return &messageKeys{
		CipherKey: okm[:32],
		MacKey:    okm[32:64],
		Iv:        okm[64:],
		Index:     c.Index,
	}, nil
}

type derivedKeys struct {
	rootKey  rootKey
	chainKey chainKey
}

func calculateDerivedKeys(version byte, keyMaterial []byte) (*derivedKeys, error) {
	b, err := DeriveSecrets(keyMaterial, nil, []byte("WhisperText"), 64)
	if err != nil {
		return nil, err
	}
	dk := &derivedKeys{}
	copy(dk.rootKey.Key[:], b[:32])
	copy(dk.chainKey.Key[:], b[32:])
	dk.chainKey.Index = 0
	return dk, nil
}

// DeriveSecrets derives the requested number of bytes using HKDF, given
// the inputKeyMaterial, salt and the info
func DeriveSecrets(inputKeyMaterial, salt, info []byte, size int) ([]byte, error) {
	hkdf := hkdf.New(sha256.New, inputKeyMaterial, salt, info)

	secrets := make([]byte, size)
	n, err := io.ReadFull(hkdf, secrets)
	if err != nil {
		return nil, err
	}
	if n != size {
		return nil, err
	}
	return secrets, nil
}

var diversifier = [32]byte{
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}

func calculateAgreement(result, theirPub, ourPriv *[32]byte) {
	curve25519.ScalarMult(result, ourPriv, theirPub)
}

func initializeSenderSession(ss *sessionState, version byte, parameters aliceAxolotlParameters) error {
	ss.setSessionVersion(uint32(version))
	ss.setLocalIdentityPublic(&parameters.OurIdentityKey.PublicKey)
	ss.setRemoteIdentityPublic(parameters.TheirIdentity)

	result := make([]byte, 0, 32*5)
	var sharedKey [32]byte
	if version >= 3 {
		result = append(result, diversifier[:]...)
	}
	calculateAgreement(&sharedKey, parameters.TheirSignedPreKey.Key(), parameters.OurIdentityKey.PrivateKey.Key())
	result = append(result, sharedKey[:]...)
	calculateAgreement(&sharedKey, parameters.TheirIdentity.Key(), parameters.OurBaseKey.PrivateKey.Key())
	result = append(result, sharedKey[:]...)
	calculateAgreement(&sharedKey, parameters.TheirSignedPreKey.Key(), parameters.OurBaseKey.PrivateKey.Key())
	result = append(result, sharedKey[:]...)

	if version >= 3 && parameters.TheirOneTimePreKey != nil {
		calculateAgreement(&sharedKey, parameters.TheirOneTimePreKey.Key(), parameters.OurBaseKey.PrivateKey.Key())
		result = append(result, sharedKey[:]...)
	}

	dk, err := calculateDerivedKeys(version, result)
	if err != nil {
		return err
	}

	sendingRatchetKey := NewECKeyPair()
	sendingChain, err := dk.rootKey.createChain(parameters.TheirRatchetKey, sendingRatchetKey)
	if err != nil {
		return err
	}

	ss.addReceiverChain(parameters.TheirRatchetKey, &sendingChain.chainKey)
	ss.setSenderChain(sendingRatchetKey, &sendingChain.chainKey)
	ss.setRootKey(&sendingChain.rootKey)

	return nil
}

func initializeReceiverSession(ss *sessionState, version byte, parameters bobAxolotlParameters) error {
	ss.setSessionVersion(uint32(version))
	ss.setLocalIdentityPublic(&parameters.OurIdentityKey.PublicKey)
	ss.setRemoteIdentityPublic(parameters.TheirIdentity)
	result := make([]byte, 0, 32*5)
	var sharedKey [32]byte
	if version >= 3 {
		result = append(result, diversifier[:]...)
	}
	calculateAgreement(&sharedKey, parameters.TheirIdentity.Key(), parameters.OurSignedPreKey.PrivateKey.Key())
	result = append(result, sharedKey[:]...)
	calculateAgreement(&sharedKey, parameters.TheirBaseKey.Key(), parameters.OurIdentityKey.PrivateKey.Key())
	result = append(result, sharedKey[:]...)
	calculateAgreement(&sharedKey, parameters.TheirBaseKey.Key(), parameters.OurSignedPreKey.PrivateKey.Key())
	result = append(result, sharedKey[:]...)

	if version >= 3 && parameters.OurOneTimePreKey != nil {
		calculateAgreement(&sharedKey, parameters.TheirBaseKey.Key(), parameters.OurOneTimePreKey.PrivateKey.Key())
		result = append(result, sharedKey[:]...)
	}
	dk, err := calculateDerivedKeys(version, result)
	if err != nil {
		return err
	}
	ss.setSenderChain(parameters.OurRatchetKey, &dk.chainKey)
	ss.setRootKey(&dk.rootKey)
	return nil
}
