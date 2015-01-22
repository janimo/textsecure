// Copyright (c) 2014 Canonical Ltd.
// Licensed under the GPLv3, see the COPYING file for details.

package axolotl

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
)

func hexToBytes(h string) []byte {
	b, err := hex.DecodeString(h)
	if err != nil {
		return nil
	}
	return b
}

var (
	key        = hexToBytes("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
	iv         = hexToBytes("000102030405060708090a0b0c0d0e0f")
	plaintext  = hexToBytes("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710")
	ciphertext = hexToBytes("f58c4c04d6e5f1ba779eabfb5f7bfbd69cfc4e967edb808d679f777bc6702c7d39f23369a9d9bacfa530e26304231461b2eb05e2c39be9fcda6c19078c6a9d1b3f461796d6b0d6b2e0c2a72b4d80e644")
)

func TestEncrypt(t *testing.T) {
	c, _ := Encrypt(key, iv, plaintext)
	assert.Equal(t, ciphertext, c, "Encrypted ciphertext must match")
}

func TestDecrypt(t *testing.T) {
	p, _ := Decrypt(key, append(iv, ciphertext...))
	assert.Equal(t, plaintext, p, "Decrypted plaintext must match")
}
