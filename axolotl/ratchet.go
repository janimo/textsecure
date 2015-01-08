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

type SymmetricAxolotlParameters struct {
	OurIdentityKey IdentityKeyPair
	OurBaseKey     ECKeyPair
	OurRatchetKey  ECKeyPair

	TheirIdentity   IdentityKey
	TheirBaseKey    ECPublicKey
	TheirRatchetKey ECPublicKey
}

type AliceAxolotlParameters struct {
	OurIdentityKey *IdentityKeyPair
	OurBaseKey     *ECKeyPair

	TheirIdentity      *IdentityKey
	TheirSignedPreKey  *ECPublicKey
	TheirOneTimePreKey *ECPublicKey
	TheirRatchetKey    *ECPublicKey
}

type BobAxolotlParameters struct {
	OurIdentityKey   *IdentityKeyPair
	OurSignedPreKey  *ECKeyPair
	OurOneTimePreKey *ECKeyPair
	OurRatchetKey    *ECKeyPair

	TheirBaseKey  *ECPublicKey
	TheirIdentity *IdentityKey
}

type RootKey struct {
	Key [32]byte
}

func NewRootKey(key []byte) *RootKey {
	ensureKeyLength(key)
	rk := &RootKey{}
	copy(rk.Key[:], key)
	return rk
}

func (r *RootKey) CreateChain(theirRatchetKey *ECPublicKey, ourRatchetKey *ECKeyPair) (*DerivedKeys, error) {
	var keyMaterial [32]byte
	calculateAgreement(&keyMaterial, theirRatchetKey.Key(), ourRatchetKey.PrivateKey.Key())
	b, err := DeriveSecrets(keyMaterial[:], r.Key[:], []byte("WhisperRatchet"), 64)
	if err != nil {
		return nil, err
	}
	dk := &DerivedKeys{}
	copy(dk.RootKey.Key[:], b[:32])
	copy(dk.ChainKey.Key[:], b[32:])
	dk.ChainKey.Index = 0
	return dk, nil
}

type ChainKey struct {
	Key   [32]byte
	Index uint32
}

func NewChainKey(key []byte, index uint32) *ChainKey {
	ensureKeyLength(key)
	ck := &ChainKey{Index: index}
	copy(ck.Key[:], key)
	return ck
}

type MessageKeys struct {
	CipherKey []byte
	MacKey    []byte
	Iv        []byte
	Index     uint32
}

func NewMessageKeys(cipherKey, macKey, iv []byte, index uint32) *MessageKeys {
	return &MessageKeys{
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

func (c *ChainKey) getBaseMaterial(seed []byte) []byte {
	m := hmac.New(sha256.New, c.Key[:])
	m.Write(seed)
	return m.Sum(nil)
}

func (c *ChainKey) getNextChainKey() *ChainKey {
	b := c.getBaseMaterial(chainKeySeed)
	ck := &ChainKey{Index: c.Index + 1}
	copy(ck.Key[:], b)
	return ck
}

func (c *ChainKey) GetMessageKeys() (*MessageKeys, error) {
	b := c.getBaseMaterial(messageKeySeed)
	okm, err := DeriveSecrets(b, nil, []byte("WhisperMessageKeys"), 80)
	if err != nil {
		return nil, err
	}
	return &MessageKeys{
		CipherKey: okm[:32],
		MacKey:    okm[32:64],
		Iv:        okm[64:],
		Index:     c.Index,
	}, nil
}

type DerivedKeys struct {
	RootKey  RootKey
	ChainKey ChainKey
}

func calculateDerivedKeys(version byte, keyMaterial []byte) (*DerivedKeys, error) {
	b, err := DeriveSecrets(keyMaterial, nil, []byte("WhisperText"), 64)
	if err != nil {
		return nil, err
	}
	dk := &DerivedKeys{}
	copy(dk.RootKey.Key[:], b[:32])
	copy(dk.ChainKey.Key[:], b[32:])
	dk.ChainKey.Index = 0
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

func InitializeSenderSession(ss *SessionState, version byte, parameters AliceAxolotlParameters) error {
	ss.SetSessionVersion(uint32(version))
	ss.SetLocalIdentityPublic(&parameters.OurIdentityKey.PublicKey)
	ss.SetRemoteIdentityPublic(parameters.TheirIdentity)

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
	sendingChain, err := dk.RootKey.CreateChain(parameters.TheirRatchetKey, sendingRatchetKey)
	if err != nil {
		return err
	}

	ss.addReceiverChain(parameters.TheirRatchetKey, &sendingChain.ChainKey)
	ss.setSenderChain(sendingRatchetKey, &sendingChain.ChainKey)
	ss.SetRootKey(&sendingChain.RootKey)

	return nil
}

func InitializeReceiverSession(ss *SessionState, version byte, parameters BobAxolotlParameters) error {
	ss.SetSessionVersion(uint32(version))
	ss.SetLocalIdentityPublic(&parameters.OurIdentityKey.PublicKey)
	ss.SetRemoteIdentityPublic(parameters.TheirIdentity)
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
	ss.setSenderChain(parameters.OurRatchetKey, &dk.ChainKey)
	ss.SetRootKey(&dk.RootKey)
	return nil
}
