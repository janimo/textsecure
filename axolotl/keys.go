// Copyright (c) 2014 Canonical Ltd.
// Licensed under the GPLv3, see the COPYING file for details.

package axolotl

import (
	"fmt"

	"golang.org/x/crypto/curve25519"
)

type ECPrivateKey struct {
	key [32]byte
}

type ECPublicKey struct {
	key [32]byte
}

const djbType = 5

func ensureKeyLength(key []byte) {
	if len(key) != 32 {
		panic(fmt.Sprintf("Key length is not 32 but %d\n", len(key)))
	}
}

func NewECPrivateKey(b []byte) *ECPrivateKey {
	ensureKeyLength(b)
	k := &ECPrivateKey{}
	copy(k.key[:], b)
	return k
}

func (k *ECPrivateKey) Key() *[32]byte {
	return &k.key
}

func NewECPublicKey(b []byte) *ECPublicKey {
	ensureKeyLength(b)
	k := &ECPublicKey{}
	copy(k.key[:], b)
	return k
}

func (k *ECPublicKey) Key() *[32]byte {
	return &k.key
}

func (k *ECPublicKey) Serialize() []byte {
	return append([]byte{djbType}, k.key[:]...)
}

type ECKeyPair struct {
	PrivateKey ECPrivateKey
	PublicKey  ECPublicKey
}

// NewECKeyPair creates a key pair
func NewECKeyPair() *ECKeyPair {
	privateKey := ECPrivateKey{}
	randBytes(privateKey.key[:])

	privateKey.key[0] &= 248
	privateKey.key[31] &= 63
	privateKey.key[31] |= 64

	publicKey := ECPublicKey{}
	curve25519.ScalarBaseMult(&publicKey.key, &privateKey.key)

	return &ECKeyPair{
		PrivateKey: privateKey,
		PublicKey:  publicKey,
	}
}

// MakeECKeyPair creates a key pair
func MakeECKeyPair(privateKey, publicKey []byte) *ECKeyPair {
	return &ECKeyPair{
		PrivateKey: *NewECPrivateKey(privateKey),
		PublicKey:  *NewECPublicKey(publicKey),
	}
}

func (kp *ECKeyPair) String() string {
	return fmt.Sprintf("Public key : % 0X\nPrivate key: % 0X\n", kp.PublicKey.Key(), kp.PrivateKey.Key())
}

type IdentityKey struct {
	ECPublicKey
}

func NewIdentityKey(b []byte) *IdentityKey {
	ensureKeyLength(b)
	k := &IdentityKey{}
	copy(k.key[:], b)
	return k
}

type IdentityKeyPair struct {
	PrivateKey ECPrivateKey
	PublicKey  IdentityKey
}

func NewIdentityKeyPairFromKeys(priv, pub []byte) *IdentityKeyPair {
	return &IdentityKeyPair{
		PublicKey:  IdentityKey{*NewECPublicKey(pub)},
		PrivateKey: *NewECPrivateKey(priv),
	}
}

// GenerateIdentityKeyPair is called once at install time to generate
// the local identity keypair.
func GenerateIdentityKeyPair() *IdentityKeyPair {
	kp := NewECKeyPair()
	ikp := &IdentityKeyPair{
		PublicKey:  IdentityKey{kp.PublicKey},
		PrivateKey: kp.PrivateKey,
	}
	return ikp
}
