// Copyright (c) 2014 Canonical Ltd.
// Licensed under the GPLv3, see the COPYING file for details.

package axolotl

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TODO: pointer receivers?
// TODO: use plain map or map in struct?

// An in-memory implementation of the prekey store, useful for testing
type InMemoryPreKeyStore struct {
	s map[uint32][]byte
}

func NewInMemoryPreKeyStore() *InMemoryPreKeyStore {
	return &InMemoryPreKeyStore{
		s: make(map[uint32][]byte),
	}
}

func (impks InMemoryPreKeyStore) containsPreKey(id uint32) bool {
	_, present := impks.s[id]
	return present
}

func (impks InMemoryPreKeyStore) removePreKey(id uint32) {
	delete(impks.s, id)
}

func (impks InMemoryPreKeyStore) loadPreKey(id uint32) (*PreKeyRecord, error) {
	if !impks.containsPreKey(id) {
		return nil, fmt.Errorf("Key %d not found", id)
	}
	pkr, err := LoadPreKeyRecord(impks.s[id])
	if err != nil {
		return nil, err
	}
	return pkr, nil
}

func (impks InMemoryPreKeyStore) storePreKey(id uint32, pkr *PreKeyRecord) {
	impks.s[id], _ = pkr.Serialize()
}

func TestPreKeyStore(t *testing.T) {
	store := NewInMemoryPreKeyStore()
	regid := uint32(0x555)

	kp := NewECKeyPair()

	assert.False(t, store.containsPreKey(regid), "Store must be empty")

	pkr := NewPreKeyRecord(regid, kp)
	store.storePreKey(*pkr.Pkrs.Id, pkr)

	assert.True(t, store.containsPreKey(regid), "Store must contain regid")

	pkr, err := store.loadPreKey(regid)
	if assert.NoError(t, err) {
		assert.Equal(t, pkr.Pkrs.GetId(), regid, "The registration ids should be the same")
		assert.Equal(t, pkr.Pkrs.GetPublicKey(), kp.PublicKey.Key()[:], "The public keys should be the same")
		assert.Equal(t, pkr.Pkrs.GetPrivateKey(), kp.PrivateKey.Key()[:], "The private keys should be the same")
	}

	store.removePreKey(regid)

	assert.False(t, store.containsPreKey(regid), "Store must be empty")
}
