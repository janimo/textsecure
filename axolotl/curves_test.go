// Copyright (c) 2014 Canonical Ltd.
// Licensed under the GPLv3, see the COPYING file for details.

package axolotl

import (
	"crypto/rand"
	"testing"

	"github.com/agl/ed25519"
	"github.com/agl/ed25519/extra25519"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/curve25519"
)

func TestKeys(t *testing.T) {
	var cpriv, cpub, cpub2 [32]byte
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if assert.NoError(t, err) {
		assert.True(t, extra25519.PublicKeyToCurve25519(&cpub, pub), "Calling PublicKeyToCurve25519 failed")
		extra25519.PrivateKeyToCurve25519(&cpriv, priv)
		curve25519.ScalarBaseMult(&cpub2, &cpriv)
		assert.Equal(t, cpub, cpub2)
	}
}

func TestKeyPairs(t *testing.T) {
	var pubkey, privkey [32]byte
	ikp := GenerateIdentityKeyPair()
	copy(privkey[:], ikp.PrivateKey.Key()[:])
	curve25519.ScalarBaseMult(&pubkey, &privkey)
	assert.Equal(t, pubkey[:], ikp.PublicKey.Key()[:])
}
