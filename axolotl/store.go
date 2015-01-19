// Copyright (c) 2014 Canonical Ltd.
// Licensed under the GPLv3, see the COPYING file for details.

package axolotl

// IdentityStore provides an interface to identity information.
type IdentityStore interface {
	GetIdentityKeyPair() (*IdentityKeyPair, error)
	GetLocalRegistrationID() (uint32, error)
	SaveIdentity(string, *IdentityKey) error
	IsTrustedIdentity(string, *IdentityKey) bool
}

// PreKeyStore provides an interface to accessing the local prekeys.
type PreKeyStore interface {
	LoadPreKey(uint32) (*PreKeyRecord, error)
	StorePreKey(uint32, *PreKeyRecord) error
	ContainsPreKey(uint32) bool
	RemovePreKey(uint32)
}

// SignedPreKeyStore provides an interface to accessing the local signed prekeys.
type SignedPreKeyStore interface {
	LoadSignedPreKey(uint32) (*SignedPreKeyRecord, error)
	LoadSignedPreKeys() []SignedPreKeyRecord
	StoreSignedPreKey(uint32, *SignedPreKeyRecord) error
	ContainsSignedPreKey(uint32) bool
	RemoveSignedPreKey(uint32)
}

// SessionStore provides an interface to accessing the local session records.
type SessionStore interface {
	LoadSession(string, uint32) (*SessionRecord, error)
	GetSubDeviceSessions(string) []uint32
	StoreSession(string, uint32, *SessionRecord) error
	ContainsSession(string, uint32) bool
	DeleteSession(string, uint32)
	DeleteAllSessions(string)
}
