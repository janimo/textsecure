package curve25519sign

import (
	"crypto/rand"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/curve25519"
)

func randBytes(data []byte) {
	if _, err := io.ReadFull(rand.Reader, data); err != nil {
		panic(err)
	}
}

func TestSign(t *testing.T) {
	msg := make([]byte, 200)

	var priv, pub [32]byte
	var random [64]byte

	// Test for random values of the keys, nonce and message
	for i := 0; i < 100; i++ {
		randBytes(priv[:])
		priv[0] &= 248
		priv[31] &= 63
		priv[31] |= 64
		curve25519.ScalarBaseMult(&pub, &priv)
		randBytes(random[:])
		randBytes(msg)
		sig := Sign(&priv, msg, random)
		v := Verify(pub, msg, sig)
		assert.True(t, v, "Verify must work")

	}
}
