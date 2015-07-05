// Copyright (c) 2014 Canonical Ltd.
// Licensed under the GPLv3, see the COPYING file for details.

package textsecure

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// randBytes returns a sequence of random bytes from the CSPRNG
func randBytes(data []byte) {
	if _, err := io.ReadFull(rand.Reader, data); err != nil {
		panic(err)
	}
}

// randUint32 returns a random 32bit uint from the CSPRNG
func randUint32() uint32 {
	b := make([]byte, 4)
	_, err := rand.Read(b)
	if err != nil {
		panic(err)
	}
	return binary.BigEndian.Uint32(b)
}

// appendMAC returns the given message with a HMAC-SHA256 MAC appended
func appendMAC(key, b []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(b)
	return m.Sum(b)
}

// verifyMAC verifies a HMAC-SHA256 MAC on a message
func verifyMAC(key, b, mac []byte) bool {
	m := hmac.New(sha256.New, key)
	m.Write(b)
	return hmac.Equal(m.Sum(nil), mac)
}

// telToToken calculates a truncated SHA1 hash of a phone number, to be used for contact discovery
func telToToken(tel string) string {
	s := sha1.Sum([]byte(tel))
	return base64EncWithoutPadding(s[:10])
}

// aesEncrypt encrypts the given plaintext under the given key in AES-CBC mode
func aesEncrypt(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	pad := aes.BlockSize - len(plaintext)%aes.BlockSize
	plaintext = append(plaintext, bytes.Repeat([]byte{byte(pad)}, pad)...)

	ciphertext := make([]byte, len(plaintext))
	iv := make([]byte, 16)
	randBytes(iv)

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, plaintext)

	return append(iv, ciphertext...), nil
}

// aesDecrypt decrypts the given ciphertext under the given key in AES-CBC mode
func aesDecrypt(key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, errors.New("Ciphertext not multiple of AES blocksize")
	}

	iv := ciphertext[:aes.BlockSize]
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(ciphertext, ciphertext)
	pad := ciphertext[len(ciphertext)-1]
	if pad > aes.BlockSize {
		return nil, fmt.Errorf("Pad value (%d) larger than AES blocksize (%d)", pad, aes.BlockSize)
	}
	return ciphertext[aes.BlockSize : len(ciphertext)-int(pad)], nil
}
