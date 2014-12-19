// Copyright (c) 2014 Canonical Ltd.
// Licensed under the GPLv3, see the COPYING file for details.

package axolotl

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMakeVersionByte(t *testing.T) {
	assert.Equal(t, byte(0x12), makeVersionByte(1, 2), "Make version byte")
}
