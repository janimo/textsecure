// Copyright (c) 2014 Canonical Ltd.
// Licensed under the GPLv3, see the COPYING file for details.

package axolotl

import (
	"fmt"

	"golang.org/x/crypto/curve25519"
)

// ECPrivateKey represents a 256 bit Curve25519 private key.
type ECPrivateKey struct {
	key [32]byte
}

// ECPublicKey represents a 256 bit Curve25519 public key.
type ECPublicKey struct {
	key [32]byte
}

const djbType = 5

func ensureKeyLength(key []byte) {
	if len(key) != 32 {
		panic(fmt.Sprintf("Key length is not 32 but %d\n", len(key)))
	}
}

// NewECPrivateKey initializes a private key with the given value.
func NewECPrivateKey(b []byte) *ECPrivateKey {
	ensureKeyLength(b)
	k := &ECPrivateKey{}
	copy(k.key[:], b)
	return k
}

// Key returns the value of the private key.
func (k *ECPrivateKey) Key() *[32]byte {
	return &k.key
}

// NewECPublicKey initializes a public key with the given value.
func NewECPublicKey(b []byte) *ECPublicKey {
	ensureKeyLength(b)
	k := &ECPublicKey{}
	copy(k.key[:], b)
	return k
}

// Key returns the value of the public key.
func (k *ECPublicKey) Key() *[32]byte {
	return &k.key
}

// Serialize returns the public key prepended by the byte value 5,
// as used in the TextSecure network protocol.
func (k *ECPublicKey) Serialize() []byte {
	return append([]byte{djbType}, k.key[:]...)
}

// ECKeyPair represents a public and private key pair.
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

// MakeECKeyPair creates a key pair.
func MakeECKeyPair(privateKey, publicKey []byte) *ECKeyPair {
	return &ECKeyPair{
		PrivateKey: *NewECPrivateKey(privateKey),
		PublicKey:  *NewECPublicKey(publicKey),
	}
}

func (kp *ECKeyPair) String() string {
	return fmt.Sprintf("Public key : % 0X\nPrivate key: % 0X\n", kp.PublicKey.Key(), kp.PrivateKey.Key())
}

// IdentityKey represents a Curve25519 public key used as a public identity.
type IdentityKey struct {
	ECPublicKey
}

// NewIdentityKey initializes an identity key to a given value.
func NewIdentityKey(b []byte) *IdentityKey {
	ensureKeyLength(b)
	k := &IdentityKey{}
	copy(k.key[:], b)
	return k
}

// IdentityKeyPair is a pair of private and public identity keys.
type IdentityKeyPair struct {
	PrivateKey ECPrivateKey
	PublicKey  IdentityKey
}

// NewIdentityKeyPairFromKeys initializes an identity key pair.
func NewIdentityKeyPairFromKeys(priv, pub []byte) *IdentityKeyPair {
	return &IdentityKeyPair{
		PublicKey:  IdentityKey{*NewECPublicKey(pub)},
		PrivateKey: *NewECPrivateKey(priv),
	}
}

// GenerateIdentityKeyPair is called once at install time to generate
// the local identity keypair, which will be valid until a reinstallation.
func GenerateIdentityKeyPair() *IdentityKeyPair {
	kp := NewECKeyPair()
	ikp := &IdentityKeyPair{
		PublicKey:  IdentityKey{kp.PublicKey},
		PrivateKey: kp.PrivateKey,
	}
	return ikp
}
