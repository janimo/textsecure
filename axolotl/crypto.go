// Copyright (c) 2014 Canonical Ltd.
// Licensed under the GPLv3, see the COPYING file for details.

package axolotl

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
)

func randBytes(data []byte) {
	if _, err := io.ReadFull(rand.Reader, data); err != nil {
		panic(err)
	}
}

// Decrypt returns the AES-CBC decryption of a ciphertext under a given key.
func Decrypt(key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, errors.New("Not multiple of AES blocksize")
	}

	iv := ciphertext[:aes.BlockSize]
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(ciphertext, ciphertext)
	pad := ciphertext[len(ciphertext)-1]
	if pad > aes.BlockSize {
		return nil, errors.New("Pad value larger than AES blocksize")
	}
	return ciphertext[aes.BlockSize : len(ciphertext)-int(pad)], nil
}

// Encrypt returns the AES-CBC encryption of a plaintext under a given key.
func Encrypt(key, iv, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	pad := aes.BlockSize - len(plaintext)%aes.BlockSize
	plaintext = append(plaintext, bytes.Repeat([]byte{byte(pad)}, pad)...)
	ciphertext := make([]byte, len(plaintext))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, plaintext)
	return ciphertext, nil
}

// ValidTruncMAC checks whether a message is correctly authenticated using HMAC-SHA256.
func ValidTruncMAC(msg, expectedMAC, key []byte) bool {
	actualMAC := ComputeTruncatedMAC(msg, key, len(expectedMAC))
	return hmac.Equal(actualMAC, expectedMAC)
}

// ComputeTruncatedMAC computes a HMAC-SHA256 MAC and returns its prefix of a given size.
func ComputeTruncatedMAC(msg, key []byte, size int) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(msg)
	return m.Sum(nil)[:size]
}
