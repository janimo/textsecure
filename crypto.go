// Copyright (c) 2014 Canonical Ltd.
// Licensed under the GPLv3, see the COPYING file for details.

package textsecure

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"log"
)

func randBytes(data []byte) {
	if _, err := io.ReadFull(rand.Reader, data); err != nil {
		panic(err)
	}
}

func randUint32() uint32 {
	b := make([]byte, 4)
	_, err := rand.Read(b)
	if err != nil {
		log.Fatal("Cannot read 4 random bytes")
	}
	return binary.BigEndian.Uint32(b)
}

// returns the given message with a MAC appended
func appendMAC(key, b []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(b)
	return m.Sum(b)
}

//verifies a MAC
func verifyMAC(key, b, mac []byte) bool {
	m := hmac.New(sha256.New, key)
	m.Write(b)
	return hmac.Equal(m.Sum(nil), mac)
}

func telToToken(tel string) string {
	s := sha1.Sum([]byte(tel))
	return base64EncWithoutPadding(s[:10])
}
