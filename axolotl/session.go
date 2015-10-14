// Copyright (c) 2014 Canonical Ltd.
// Licensed under the GPLv3, see the COPYING file for details.

// Package axolotl implements the Axolotl ratchet as used by TextSecure protocol version 3.
package axolotl

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/golang/protobuf/proto"
	protobuf "github.com/janimo/textsecure/axolotl/protobuf"
	"github.com/janimo/textsecure/curve25519sign"
	"github.com/janimo/textsecure/protobuf"
)

type sessionState struct {
	SS *protobuf.SessionStructure
}

func newSessionState(ss *protobuf.SessionStructure) *sessionState {
	return &sessionState{SS: ss}
}

func (ss *sessionState) setAliceBaseKey(key []byte) {
	ss.SS.AliceBaseKey = key
}

func (ss *sessionState) getAliceBaseKey() []byte {
	return ss.SS.GetAliceBaseKey()
}

func (ss *sessionState) setSessionVersion(version uint32) {
	ss.SS.SessionVersion = &version
}

func (ss *sessionState) getSessionVersion() uint32 {
	version := ss.SS.GetSessionVersion()
	if version == 0 {
		version = 2
	}
	return version
}

func (ss *sessionState) setPreviousCounter(pc uint32) {
	ss.SS.PreviousCounter = &pc
}

func (ss *sessionState) getPreviousCounter() uint32 {
	return ss.SS.GetPreviousCounter()
}

func (ss *sessionState) setLocalIdentityPublic(key *IdentityKey) {
	ss.SS.LocalIdentityPublic = key.Key()[:]
}

func (ss *sessionState) getLocalIdentityPublic() *IdentityKey {
	return NewIdentityKey(ss.SS.GetLocalIdentityPublic())
}

func (ss *sessionState) setRemoteIdentityPublic(key *IdentityKey) {
	ss.SS.RemoteIdentityPublic = key.Key()[:]
}

func (ss *sessionState) getRemoteIdentityPublic() *IdentityKey {
	return NewIdentityKey(ss.SS.GetRemoteIdentityPublic())
}

func (ss *sessionState) setRootKey(rk *rootKey) {
	ss.SS.RootKey = rk.Key[:]
}

func (ss *sessionState) getRootKey() *rootKey {
	return newRootKey(ss.SS.GetRootKey())
}

func (ss *sessionState) setLocalRegistrationID(id uint32) {
	ss.SS.LocalRegistrationId = &id
}

func (ss *sessionState) getLocalRegistrationID() uint32 {
	return *ss.SS.LocalRegistrationId
}

func (ss *sessionState) setRemoteRegistrationID(id uint32) {
	ss.SS.RemoteRegistrationId = &id
}

func (ss *sessionState) getRemoteRegistrationID() uint32 {
	return *ss.SS.RemoteRegistrationId
}

func (ss *sessionState) getSenderRatchetKey() *ECPublicKey {
	return NewECPublicKey(ss.SS.GetSenderChain().GetSenderRatchetKey())
}

func (ss *sessionState) getSenderRatchetKeyPair() *ECKeyPair {
	priv := ss.SS.GetSenderChain().GetSenderRatchetKeyPrivate()
	pub := ss.SS.GetSenderChain().GetSenderRatchetKey()
	return MakeECKeyPair(priv, pub)
}

func (ss *sessionState) hasSenderChain() bool {
	return ss.SS.GetSenderChain() != nil
}

func (ss *sessionState) hasReceiverChain(senderEphemeral *ECPublicKey) bool {
	rc, _ := ss.getReceiverChain(senderEphemeral)
	return rc != nil
}

func (ss *sessionState) getReceiverChain(key *ECPublicKey) (*protobuf.SessionStructure_Chain, uint32) {
	for i, rc := range ss.SS.ReceiverChains {
		if bytes.Equal(key.key[:], rc.GetSenderRatchetKey()) {
			return rc, uint32(i)
		}
	}
	return nil, 0
}

func (ss *sessionState) getReceiverChainKey(senderEphemeral *ECPublicKey) *chainKey {
	rc, _ := ss.getReceiverChain(senderEphemeral)
	if rc == nil {
		return nil
	}
	return newChainKey(rc.GetChainKey().Key, *rc.GetChainKey().Index)

}

func (ss *sessionState) setReceiverChainKey(senderEphemeral *ECPublicKey, chainKey *chainKey) {
	rc, _ := ss.getReceiverChain(senderEphemeral)
	rc.ChainKey = &protobuf.SessionStructure_Chain_ChainKey{
		Index: &chainKey.Index,
		Key:   chainKey.Key[:],
	}
}

func (ss *sessionState) addReceiverChain(senderRatchetKey *ECPublicKey, chainKey *chainKey) {
	ck := &protobuf.SessionStructure_Chain_ChainKey{Index: &chainKey.Index,
		Key: chainKey.Key[:],
	}

	c := &protobuf.SessionStructure_Chain{ChainKey: ck,
		SenderRatchetKey: senderRatchetKey.key[:],
	}
	ss.SS.ReceiverChains = append(ss.SS.ReceiverChains, c)
	if len(ss.SS.ReceiverChains) > 5 {
		ss.SS.ReceiverChains = ss.SS.ReceiverChains[1:]
	}
}

func (ss *sessionState) setSenderChain(kp *ECKeyPair, ck *chainKey) {
	ss.SS.SenderChain = &protobuf.SessionStructure_Chain{
		SenderRatchetKey:        kp.PublicKey.Key()[:],
		SenderRatchetKeyPrivate: kp.PrivateKey.Key()[:],
		ChainKey: &protobuf.SessionStructure_Chain_ChainKey{
			Index: &ck.Index,
			Key:   ck.Key[:],
		},
	}
}

func (ss *sessionState) getSenderChainKey() *chainKey {
	ssck := ss.SS.GetSenderChain().GetChainKey()
	return newChainKey(ssck.Key, *ssck.Index)
}

func (ss *sessionState) setSenderChainKey(ck *chainKey) {
	ss.SS.SenderChain.ChainKey = &protobuf.SessionStructure_Chain_ChainKey{
		Index: &ck.Index,
		Key:   ck.Key[:],
	}
}

func (ss *sessionState) hasMessageKeys(senderEphemeral *ECPublicKey, counter uint32) bool {
	rc, _ := ss.getReceiverChain(senderEphemeral)
	if rc == nil {
		return false
	}
	for _, mk := range rc.GetMessageKeys() {
		if counter == mk.GetIndex() {
			return true
		}
	}
	return false
}

func (ss *sessionState) removeMessageKeys(senderEphemeral *ECPublicKey, counter uint32) *messageKeys {
	rc, _ := ss.getReceiverChain(senderEphemeral)
	if rc == nil {
		return nil
	}
	for i, mk := range rc.GetMessageKeys() {
		if counter == mk.GetIndex() {
			rc.MessageKeys = append(rc.MessageKeys[:i], rc.MessageKeys[i+1:]...)
			return newMessageKeys(mk.GetCipherKey(), mk.GetMacKey(), mk.GetIv(), mk.GetIndex())
		}
	}
	return nil
}

func (ss *sessionState) setMessageKeys(senderEphemeral *ECPublicKey, mk *messageKeys) {
	rc, _ := ss.getReceiverChain(senderEphemeral)
	sscmk := &protobuf.SessionStructure_Chain_MessageKey{
		CipherKey: mk.CipherKey,
		MacKey:    mk.MacKey,
		Iv:        mk.Iv,
		Index:     &mk.Index,
	}

	rc.MessageKeys = append(rc.MessageKeys, sscmk)
}

type unacknowledgedPreKeyMessageItem struct {
	preKeyID       uint32
	signedPreKeyID int32
	baseKey        *ECPublicKey
}

func (ss *sessionState) hasUnacknowledgedPreKeyMessage() bool {
	return ss.SS.GetPendingPreKey() != nil
}

func (ss *sessionState) getUnacknowledgedPreKeyMessageItems() *unacknowledgedPreKeyMessageItem {
	preKeyID := uint32(0)
	ppk := ss.SS.GetPendingPreKey()

	if ppk.PreKeyId != nil {
		preKeyID = *ppk.PreKeyId
	}

	return &unacknowledgedPreKeyMessageItem{preKeyID, ppk.GetSignedPreKeyId(), NewECPublicKey(ppk.GetBaseKey()[1:])}
}

func (ss *sessionState) setUnacknowledgedPreKeyMessage(preKeyID uint32, signedPreKeyID int32, ourBaseKey *ECPublicKey) {
	ssppk := &protobuf.SessionStructure_PendingPreKey{
		SignedPreKeyId: &signedPreKeyID,
		BaseKey:        ourBaseKey.Serialize(),
	}
	if preKeyID != 0 {
		ssppk.PreKeyId = &preKeyID
	}
	ss.SS.PendingPreKey = ssppk
}

func (ss *sessionState) clearUnacknowledgedPreKeyMessage() {
	ss.SS.PendingPreKey = nil
}

// SessionRecord represents a session in persistent store.
type SessionRecord struct {
	sessionState   *sessionState
	PreviousStates []*sessionState
	Fresh          bool
}

// NewSessionRecord creates a new SessionRecord object.
func NewSessionRecord() *SessionRecord {
	ss := &protobuf.SessionStructure{}
	record := &SessionRecord{sessionState: &sessionState{ss},
		Fresh: true,
	}
	return record
}

// LoadSessionRecord creates a SessionRecord object from serialized byte, error) {
func LoadSessionRecord(serialized []byte) (*SessionRecord, error) {
	rs := &protobuf.RecordStructure{}

	err := proto.Unmarshal(serialized, rs)
	if err != nil {
		return nil, err
	}
	record := &SessionRecord{sessionState: newSessionState(rs.CurrentSession)}
	for _, s := range rs.PreviousSessions {
		record.PreviousStates = append(record.PreviousStates, newSessionState(s))
	}
	return record, nil
}

// Serialize saves the state of a SessionRecord object to a byte stream.
func (record *SessionRecord) Serialize() ([]byte, error) {
	rs := &protobuf.RecordStructure{}
	rs.CurrentSession = record.sessionState.SS
	for _, s := range record.PreviousStates {
		rs.PreviousSessions = append(rs.PreviousSessions, s.SS)
	}
	b, err := proto.Marshal(rs)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func (record *SessionRecord) hasSessionState(version uint32, key []byte) bool {
	if record.sessionState.getSessionVersion() == version &&
		bytes.Equal(key, record.sessionState.getAliceBaseKey()) {
		return true
	}
	for _, ss := range record.PreviousStates {
		if ss.getSessionVersion() == version &&
			bytes.Equal(key, ss.getAliceBaseKey()) {
			return true
		}
	}
	return false
}

func (record *SessionRecord) promoteState(promotedState *sessionState) {
	record.PreviousStates = append([]*sessionState{record.sessionState}, record.PreviousStates...)
	if len(record.PreviousStates) > 40 {
		record.PreviousStates = record.PreviousStates[:len(record.PreviousStates)-1]
	}
	record.sessionState = promotedState
}

func (record *SessionRecord) archiveCurrentState() {
	record.promoteState(newSessionState(&protobuf.SessionStructure{}))
}

// SessionBuilder takes care of creating the sessions.
type SessionBuilder struct {
	identityStore     IdentityStore
	preKeyStore       PreKeyStore
	signedPreKeyStore SignedPreKeyStore
	sessionStore      SessionStore
	recipientID       string
	deviceID          uint32
}

// NewSessionBuilder creates a new session builder object.
func NewSessionBuilder(identityStore IdentityStore, preKeyStore PreKeyStore, signedPreKeyStore SignedPreKeyStore, sessionStore SessionStore, recipientID string, deviceID uint32) *SessionBuilder {
	return &SessionBuilder{
		identityStore:     identityStore,
		preKeyStore:       preKeyStore,
		signedPreKeyStore: signedPreKeyStore,
		sessionStore:      sessionStore,
		recipientID:       recipientID,
		deviceID:          deviceID,
	}
}

// NotTrustedError represents the error situation where the peer
// is using a different identity key than expected.
type NotTrustedError struct {
	ID string
}

func (err NotTrustedError) Error() string {
	return fmt.Sprintf("remote identity %s is not trusted", err.ID)
}

// UnsupportedVersionError represents the error situation where the peer
// is using an unsupported protocol version.
type UnsupportedVersionError struct {
	version byte
}

func (err UnsupportedVersionError) Error() string {
	return fmt.Sprintf("unsupported protocol version %d", err.version)
}

// PreKeyNotFoundError represents the error situation when a local prekey cannot be loaded.
type PreKeyNotFoundError struct {
	pkid    uint32
	details error
}

func (err PreKeyNotFoundError) Error() string {
	return fmt.Sprintf("prekey %d could not be found (%s)", err.pkid, err.details)
}

// BuildReceiverSession creates a new session from a received PreKeyWhisperMessage.
func (sb *SessionBuilder) BuildReceiverSession(sr *SessionRecord, pkwm *PreKeyWhisperMessage) (uint32, error) {
	if pkwm.Version != currentVersion {
		return 0, UnsupportedVersionError{pkwm.Version}
	}
	theirIdentityKey := pkwm.IdentityKey
	if !sb.identityStore.IsTrustedIdentity(sb.recipientID, theirIdentityKey) {
		return 0, NotTrustedError{sb.recipientID}
	}
	if sr.hasSessionState(uint32(pkwm.Version), pkwm.BaseKey.Serialize()) {
		return 0, nil
	}
	ourSignedPreKey, err := sb.signedPreKeyStore.LoadSignedPreKey(pkwm.SignedPreKeyID)
	if err != nil {
		return 0, err
	}
	ourIdentityKey, err := sb.identityStore.GetIdentityKeyPair()
	if err != nil {
		return 0, err
	}
	bob := bobAxolotlParameters{
		TheirBaseKey:    pkwm.BaseKey,
		TheirIdentity:   pkwm.IdentityKey,
		OurIdentityKey:  ourIdentityKey,
		OurSignedPreKey: ourSignedPreKey.getKeyPair(),
		OurRatchetKey:   ourSignedPreKey.getKeyPair(),
	}
	if pkwm.PreKeyID != 0 {
		pk, err := sb.preKeyStore.LoadPreKey(pkwm.PreKeyID)
		if err != nil {
			return 0, PreKeyNotFoundError{pkwm.PreKeyID, err}
		}
		bob.OurOneTimePreKey = pk.getKeyPair()
	}
	if !sr.Fresh {
		sr.archiveCurrentState()
	}
	err = initializeReceiverSession(sr.sessionState, pkwm.Version, bob)
	if err != nil {
		return 0, err
	}

	regID, err := sb.identityStore.GetLocalRegistrationID()
	if err != nil {
		return 0, err
	}
	sr.sessionState.setLocalRegistrationID(regID)
	sr.sessionState.setRemoteRegistrationID(pkwm.RegistrationID)
	sr.sessionState.setAliceBaseKey(pkwm.BaseKey.Serialize())

	err = sb.identityStore.SaveIdentity(sb.recipientID, theirIdentityKey)
	if err != nil {
		return 0, err
	}

	return pkwm.PreKeyID, nil
}

// InvalidSignatureError represents the error situation where the verification
// of the sender identity fails.
type InvalidSignatureError struct {
	pkb *PreKeyBundle
}

func (err InvalidSignatureError) Error() string {
	return fmt.Sprintf("invalid signature on prekey %d", err.pkb.PreKeyID)
}

// BuildSenderSession creates a new session from a PreKeyBundle
func (sb *SessionBuilder) BuildSenderSession(pkb *PreKeyBundle) error {
	theirIdentityKey := pkb.IdentityKey
	if !sb.identityStore.IsTrustedIdentity(sb.recipientID, theirIdentityKey) {
		return NotTrustedError{sb.recipientID}
	}
	if pkb.SignedPreKeyPublic != nil &&
		!curve25519sign.Verify(*theirIdentityKey.Key(), pkb.SignedPreKeyPublic.Serialize(), &pkb.SignedPreKeySignature) {
		return InvalidSignatureError{pkb}
	}

	sr, err := sb.sessionStore.LoadSession(sb.recipientID, sb.deviceID)
	if err != nil {
		return err
	}
	ourBaseKey := NewECKeyPair()
	theirSignedPreKey := pkb.SignedPreKeyPublic
	theirOneTimePreKey := pkb.PreKeyPublic
	theirOneTimePreKeyID := pkb.PreKeyID

	ourIdentityKey, err := sb.identityStore.GetIdentityKeyPair()
	if err != nil {
		return err
	}
	alice := aliceAxolotlParameters{
		OurBaseKey:         ourBaseKey,
		OurIdentityKey:     ourIdentityKey,
		TheirIdentity:      pkb.IdentityKey,
		TheirSignedPreKey:  theirSignedPreKey,
		TheirRatchetKey:    theirSignedPreKey,
		TheirOneTimePreKey: theirOneTimePreKey,
	}

	if !sr.Fresh {
		sr.archiveCurrentState()
	}

	err = initializeSenderSession(sr.sessionState, 3, alice)
	if err != nil {
		return err
	}

	sr.sessionState.setUnacknowledgedPreKeyMessage(theirOneTimePreKeyID, pkb.SignedPreKeyID, &ourBaseKey.PublicKey)
	regID, err := sb.identityStore.GetLocalRegistrationID()
	if err != nil {
		return err
	}
	sr.sessionState.setLocalRegistrationID(regID)
	sr.sessionState.setRemoteRegistrationID(pkb.RegistrationID)
	sr.sessionState.setAliceBaseKey(ourBaseKey.PublicKey.Serialize())

	err = sb.sessionStore.StoreSession(sb.recipientID, sb.deviceID, sr)
	if err != nil {
		return err
	}
	err = sb.identityStore.SaveIdentity(sb.recipientID, theirIdentityKey)
	return err
}

// SessionCipher represents a peer and its persistent stored session.
type SessionCipher struct {
	RecipientID  string
	DeviceID     uint32
	SessionStore SessionStore
	PreKeyStore  PreKeyStore
	Builder      *SessionBuilder
}

// NewSessionCipher creates a new session cipher.
func NewSessionCipher(identityStore IdentityStore, preKeyStore PreKeyStore, signedPreKeyStore SignedPreKeyStore, sessionStore SessionStore, recipientID string, deviceID uint32) *SessionCipher {
	return &SessionCipher{
		RecipientID:  recipientID,
		DeviceID:     deviceID,
		SessionStore: sessionStore,
		PreKeyStore:  preKeyStore,
		Builder:      NewSessionBuilder(identityStore, preKeyStore, signedPreKeyStore, sessionStore, recipientID, deviceID),
	}
}

// SessionEncryptMessage encrypts a given plaintext in a WhisperMessage or a PreKeyWhisperMessage,
// depending on whether there a session with the peer exists or needs to be established.
func (sc *SessionCipher) SessionEncryptMessage(plaintext []byte) ([]byte, int32, error) {
	sc.SessionStore.Lock()
	defer sc.SessionStore.Unlock()

	sr, err := sc.SessionStore.LoadSession(sc.RecipientID, sc.DeviceID)
	if err != nil {
		return nil, 0, err
	}
	ss := sr.sessionState
	chainKey := ss.getSenderChainKey()
	messageKeys, err := chainKey.getMessageKeys()
	if err != nil {
		return nil, 0, err
	}
	senderEphemeral := ss.getSenderRatchetKey()
	previousCounter := ss.getPreviousCounter()
	ciphertext, err := Encrypt(messageKeys.CipherKey, messageKeys.Iv, plaintext)
	if err != nil {
		return nil, 0, err
	}
	version := ss.getSessionVersion()

	wm, err := newWhisperMessage(byte(version), messageKeys.MacKey, senderEphemeral, chainKey.Index,
		previousCounter, ciphertext, ss.getLocalIdentityPublic(), ss.getRemoteIdentityPublic())
	if err != nil {
		return nil, 0, err
	}
	msg := wm.serialize()
	msgType := int32(textsecure.Envelope_CIPHERTEXT)

	if ss.hasUnacknowledgedPreKeyMessage() {
		items := ss.getUnacknowledgedPreKeyMessageItems()
		pkwm, err := newPreKeyWhisperMessage(byte(version), ss.getLocalRegistrationID(),
			items.preKeyID, uint32(items.signedPreKeyID), items.baseKey,
			ss.getLocalIdentityPublic(), wm)
		if err != nil {
			return nil, 0, nil
		}
		msg = pkwm.serialize()
		msgType = int32(textsecure.Envelope_PREKEY_BUNDLE)
	}

	ss.setSenderChainKey(chainKey.getNextChainKey())
	err = sc.SessionStore.StoreSession(sc.RecipientID, sc.DeviceID, sr)
	if err != nil {
		return nil, 0, err
	}

	return msg, msgType, nil
}

// GetRemoteRegistrationID returns the registration ID of the peer.
func (sc *SessionCipher) GetRemoteRegistrationID() (uint32, error) {
	sr, err := sc.SessionStore.LoadSession(sc.RecipientID, sc.DeviceID)
	if err != nil {
		return 0, err
	}
	return sr.sessionState.getRemoteRegistrationID(), nil
}

// ErrUninitializedSession occurs when there is no session matching the incoming message.
var ErrUninitializedSession = errors.New("uninitialized session")

// MismatchedVersionError represents the error situation where the peer
// is using a different protocol version.
type MismatchedVersionError struct {
	cipherVersion  uint32
	sessionVersion uint32
}

func (err MismatchedVersionError) Error() string {
	return fmt.Sprintf("cipher version %d does not match session version %d", err.cipherVersion, err.sessionVersion)
}

// ErrInvalidMACForWhisperMessage signals a message with invalid MAC.
var ErrInvalidMACForWhisperMessage = errors.New("invalid MAC for WhisperMessage")

func (sc *SessionCipher) decrypt(sr *SessionRecord, ciphertext *WhisperMessage) ([]byte, error) {
	ss := sr.sessionState
	if !ss.hasSenderChain() {
		return nil, ErrUninitializedSession
	}
	if uint32(ciphertext.Version) != ss.getSessionVersion() {
		return nil, MismatchedVersionError{uint32(ciphertext.Version), ss.getSessionVersion()}
	}

	theirEphemeral := ciphertext.RatchetKey
	counter := ciphertext.Counter
	chainKey, err := getOrCreateChainKey(ss, theirEphemeral)
	if err != nil {
		return nil, err
	}
	messageKeys, err := getOrCreateMessageKeys(ss, theirEphemeral, chainKey, counter)
	if err != nil {
		return nil, err
	}

	if !ciphertext.verifyMAC(ss.getRemoteIdentityPublic(), ss.getLocalIdentityPublic(), messageKeys.MacKey) {
		return nil, ErrInvalidMACForWhisperMessage
	}
	plaintext, err := Decrypt(messageKeys.CipherKey, append(messageKeys.Iv, ciphertext.Ciphertext...))
	if err != nil {
		return nil, err
	}

	ss.clearUnacknowledgedPreKeyMessage()

	return plaintext, nil
}

// SessionDecryptWhisperMessage decrypts an incoming message.
func (sc *SessionCipher) SessionDecryptWhisperMessage(ciphertext *WhisperMessage) ([]byte, error) {
	sc.SessionStore.Lock()
	defer sc.SessionStore.Unlock()

	sr, err := sc.SessionStore.LoadSession(sc.RecipientID, sc.DeviceID)
	if err != nil {
		return nil, err
	}
	plaintext, err := sc.decrypt(sr, ciphertext)
	if err != nil {
		return nil, err
	}
	err = sc.SessionStore.StoreSession(sc.RecipientID, sc.DeviceID, sr)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

// SessionDecryptPreKeyWhisperMessage decrypts an incoming message.
func (sc *SessionCipher) SessionDecryptPreKeyWhisperMessage(ciphertext *PreKeyWhisperMessage) ([]byte, error) {
	sc.SessionStore.Lock()
	defer sc.SessionStore.Unlock()

	sr, err := sc.SessionStore.LoadSession(sc.RecipientID, sc.DeviceID)
	if err != nil {
		return nil, err
	}
	pkid, err := sc.Builder.BuildReceiverSession(sr, ciphertext)
	if err != nil {
		return nil, err
	}
	plaintext, err := sc.decrypt(sr, ciphertext.Message)
	if err != nil {
		return nil, err
	}
	if pkid != 0xFFFFFF {
		sc.PreKeyStore.RemovePreKey(pkid)
	}
	err = sc.SessionStore.StoreSession(sc.RecipientID, sc.DeviceID, sr)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

func getOrCreateChainKey(ss *sessionState, theirEphemeral *ECPublicKey) (*chainKey, error) {
	if ss.hasReceiverChain(theirEphemeral) {
		return ss.getReceiverChainKey(theirEphemeral), nil
	}

	rootKey := ss.getRootKey()
	ourEphemeral := ss.getSenderRatchetKeyPair()
	receiverChain, err := rootKey.createChain(theirEphemeral, ourEphemeral)
	if err != nil {
		return nil, err
	}

	ourNewEphemeral := NewECKeyPair()
	senderChain, err := receiverChain.rootKey.createChain(theirEphemeral, ourNewEphemeral)
	if err != nil {
		return nil, err
	}

	ss.setRootKey(&senderChain.rootKey)
	ss.addReceiverChain(theirEphemeral, &receiverChain.chainKey)
	pc := ss.getSenderChainKey().Index
	if pc > 0 {
		pc--
	}
	ss.setPreviousCounter(pc)
	ss.setSenderChain(ourNewEphemeral, &senderChain.chainKey)
	return &receiverChain.chainKey, nil
}

// DuplicateMessageError indicates that we have received the same message more than once.
type DuplicateMessageError struct {
	index   uint32
	counter uint32
}

func (err DuplicateMessageError) Error() string {
	return fmt.Sprintf("duplicate message: expected %d, got %d", err.index, err.counter)
}

func getOrCreateMessageKeys(ss *sessionState, theirEphemeral *ECPublicKey, chainKey *chainKey, counter uint32) (*messageKeys, error) {
	if chainKey.Index > counter {
		if ss.hasMessageKeys(theirEphemeral, counter) {
			return ss.removeMessageKeys(theirEphemeral, counter), nil
		}
		return nil, DuplicateMessageError{chainKey.Index, counter}
	}
	if int(counter)-int(chainKey.Index) > 2000 {
		return nil, errors.New("over 2000 messages in the future")
	}
	for chainKey.Index < counter {
		messageKeys, err := chainKey.getMessageKeys()
		if err != nil {
			return nil, err
		}
		ss.setMessageKeys(theirEphemeral, messageKeys)
		chainKey = chainKey.getNextChainKey()
	}

	ss.setReceiverChainKey(theirEphemeral, chainKey.getNextChainKey())
	return chainKey.getMessageKeys()
}
