// Copyright (c) 2014 Canonical Ltd.
// Licensed under the GPLv3, see the COPYING file for details.

package textsecure

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMAC(t *testing.T) {
	key := make([]byte, 32)
	randBytes(key)
	msg := make([]byte, 100)
	randBytes(msg)
	macced := appendMAC(key, msg)
	assert.True(t, verifyMAC(key, macced[:100], macced[100:]))
}
