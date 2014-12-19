// Copyright (c) 2014 Canonical Ltd.
// Licensed under the GPLv3, see the COPYING file for details.

// Package axolotl implements the Axolotl ratchet as used by TextSecure protocol version 3.
package axolotl

import (
	"bytes"
	"errors"
	"fmt"
	"log"

	"github.com/golang/protobuf/proto"
	protobuf "github.com/janimo/textsecure/axolotl/protobuf"
	"github.com/janimo/textsecure/curve25519sign"
)

type SessionState struct {
	SS *protobuf.SessionStructure
}

func NewSessionState(ss *protobuf.SessionStructure) *SessionState {
	return &SessionState{SS: ss}
}

func (ss *SessionState) SetAliceBaseKey(key []byte) {
	ss.SS.AliceBaseKey = key
}

func (ss *SessionState) GetAliceBaseKey() []byte {
	return ss.SS.GetAliceBaseKey()
}

func (ss *SessionState) SetSessionVersion(version uint32) {
	ss.SS.SessionVersion = &version
}

func (ss *SessionState) GetSessionVersion() uint32 {
	version := ss.SS.GetSessionVersion()
	if version == 0 {
		version = 2
	}
	return version
}

func (ss *SessionState) SetPreviousCounter(pc uint32) {
	ss.SS.PreviousCounter = &pc
}

func (ss *SessionState) GetPreviousCounter() uint32 {
	return ss.SS.GetPreviousCounter()
}

func (ss *SessionState) SetLocalIdentityPublic(key *IdentityKey) {
	ss.SS.LocalIdentityPublic = key.Key()[:]
}

func (ss *SessionState) GetLocalIdentityPublic() *IdentityKey {
	return NewIdentityKey(ss.SS.GetLocalIdentityPublic())
}

func (ss *SessionState) SetRemoteIdentityPublic(key *IdentityKey) {
	ss.SS.RemoteIdentityPublic = key.Key()[:]
}

func (ss *SessionState) GetRemoteIdentityPublic() *IdentityKey {
	return NewIdentityKey(ss.SS.GetRemoteIdentityPublic())
}

func (ss *SessionState) SetRootKey(rk *RootKey) {
	ss.SS.RootKey = rk.Key[:]
}

func (ss *SessionState) GetRootKey() *RootKey {
	return NewRootKey(ss.SS.GetRootKey())
}

func (ss *SessionState) SetLocalRegistrationId(id uint32) {
	ss.SS.LocalRegistrationId = &id
}

func (ss *SessionState) GetLocalRegistrationId() uint32 {
	return *ss.SS.LocalRegistrationId
}

func (ss *SessionState) SetRemoteRegistrationId(id uint32) {
	ss.SS.RemoteRegistrationId = &id
}

func (ss *SessionState) GetRemoteRegistrationId() uint32 {
	return *ss.SS.RemoteRegistrationId
}

func (ss *SessionState) GetSenderRatchetKey() *ECPublicKey {
	return NewECPublicKey(ss.SS.GetSenderChain().GetSenderRatchetKey())
}

func (ss *SessionState) GetSenderRatchetKeyPair() *ECKeyPair {
	priv := ss.SS.GetSenderChain().GetSenderRatchetKeyPrivate()
	pub := ss.SS.GetSenderChain().GetSenderRatchetKey()
	return MakeECKeyPair(priv, pub)
}

func (ss *SessionState) HasSenderChain() bool {
	return ss.SS.GetSenderChain() != nil
}

func (ss *SessionState) HasReceiverChain(senderEphemeral *ECPublicKey) bool {
	rc, _ := ss.GetReceiverChain(senderEphemeral)
	return rc != nil
}

func (ss *SessionState) GetReceiverChain(key *ECPublicKey) (*protobuf.SessionStructure_Chain, uint32) {
	for i, rc := range ss.SS.ReceiverChains {
		if bytes.Equal(key.key[:], rc.GetSenderRatchetKey()) {
			return rc, uint32(i)
		}
	}
	return nil, 0
}

func (ss *SessionState) GetReceiverChainKey(senderEphemeral *ECPublicKey) *ChainKey {
	rc, _ := ss.GetReceiverChain(senderEphemeral)
	if rc == nil {
		return nil
	}
	return NewChainKey(rc.GetChainKey().Key, *rc.GetChainKey().Index)

}

func (ss *SessionState) SetReceiverChainKey(senderEphemeral *ECPublicKey, chainKey *ChainKey) {
	rc, _ := ss.GetReceiverChain(senderEphemeral)
	rc.ChainKey = &protobuf.SessionStructure_Chain_ChainKey{
		Index: &chainKey.Index,
		Key:   chainKey.Key[:],
	}
}

func (ss *SessionState) AddReceiverChain(senderRatchetKey *ECPublicKey, chainKey *ChainKey) {
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

func (ss *SessionState) SetSenderChain(kp *ECKeyPair, ck *ChainKey) {
	ss.SS.SenderChain = &protobuf.SessionStructure_Chain{
		SenderRatchetKey:        kp.PublicKey.Key()[:],
		SenderRatchetKeyPrivate: kp.PrivateKey.Key()[:],
		ChainKey: &protobuf.SessionStructure_Chain_ChainKey{
			Index: &ck.Index,
			Key:   ck.Key[:],
		},
	}
}

func (ss *SessionState) GetSenderChainKey() *ChainKey {
	ssck := ss.SS.GetSenderChain().GetChainKey()
	return NewChainKey(ssck.Key, *ssck.Index)
}

func (ss *SessionState) SetSenderChainKey(ck *ChainKey) {
	ss.SS.SenderChain.ChainKey = &protobuf.SessionStructure_Chain_ChainKey{
		Index: &ck.Index,
		Key:   ck.Key[:],
	}
}

func (ss *SessionState) HasMessageKeys(senderEphemeral *ECPublicKey, counter uint32) bool {
	rc, _ := ss.GetReceiverChain(senderEphemeral)
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

func (ss *SessionState) RemoveMessageKeys(senderEphemeral *ECPublicKey, counter uint32) *MessageKeys {
	rc, _ := ss.GetReceiverChain(senderEphemeral)
	if rc == nil {
		return nil
	}
	for i, mk := range rc.GetMessageKeys() {
		if counter == mk.GetIndex() {
			/*
				//FIXME better non-leaky delete from slice, like the ugly code below
				copy(rc.MessageKeys[i:], rc.MessageKeys[i+1:])
				rc.MessageKeys[len(rc.MessageKeys)-1] = nil
				rc.MessageKeys = rc.MessageKeys[:len(rc.MessageKeys)-1]
			*/
			rc.MessageKeys = append(rc.MessageKeys[:i], rc.MessageKeys[i+1:]...)
			return NewMessageKeys(mk.GetCipherKey(), mk.GetMacKey(), mk.GetIv(), mk.GetIndex())
		}
	}
	return nil
}

func (ss *SessionState) SetMessageKeys(senderEphemeral *ECPublicKey, mk *MessageKeys) {
	rc, _ := ss.GetReceiverChain(senderEphemeral)
	sscmk := &protobuf.SessionStructure_Chain_MessageKey{
		CipherKey: mk.CipherKey,
		MacKey:    mk.MacKey,
		Iv:        mk.Iv,
		Index:     &mk.Index,
	}

	rc.MessageKeys = append(rc.MessageKeys, sscmk)
}

type UnacknowledgedPreKeyMessageItem struct {
	preKeyId       uint32
	signedPreKeyId int32
	baseKey        *ECPublicKey
}

func (ss *SessionState) HasUnacknowledgedPreKeyMessage() bool {
	return ss.SS.GetPendingPreKey() != nil
}

func (ss *SessionState) GetUnacknowledgedPreKeyMessageItems() *UnacknowledgedPreKeyMessageItem {
	preKeyId := uint32(0)
	ppk := ss.SS.GetPendingPreKey()

	if ppk.PreKeyId != nil {
		preKeyId = *ppk.PreKeyId
	}

	return &UnacknowledgedPreKeyMessageItem{preKeyId, ppk.GetSignedPreKeyId(), NewECPublicKey(ppk.GetBaseKey()[1:])}
}

func (ss *SessionState) SetUnacknowledgedPreKeyMessage(preKeyId uint32, signedPreKeyId int32, ourBaseKey *ECPublicKey) {
	ssppk := &protobuf.SessionStructure_PendingPreKey{
		SignedPreKeyId: &signedPreKeyId,
		BaseKey:        ourBaseKey.Serialize(),
	}
	if preKeyId != 0 {
		ssppk.PreKeyId = &preKeyId
	}
	ss.SS.PendingPreKey = ssppk
}

func (ss *SessionState) ClearUnacknowledgedPreKeyMessage() {
	ss.SS.PendingPreKey = nil
}

func (ss *SessionState) Serialize() []byte {
	b, err := proto.Marshal(ss.SS)
	if err != nil {
		log.Fatal("Cannot marshal SessionState", err)
	}
	return b
}

type SessionRecord struct {
	SessionState   *SessionState
	PreviousStates []*SessionState
	Fresh          bool
}

func NewSessionRecord() *SessionRecord {
	ss := &protobuf.SessionStructure{}
	record := &SessionRecord{SessionState: &SessionState{ss},
		Fresh: true,
	}
	return record
}

func LoadSessionRecord(serialized []byte) *SessionRecord {
	rs := &protobuf.RecordStructure{}

	err := proto.Unmarshal(serialized, rs)
	if err != nil {
		log.Fatal("Cannot unmarshal PreKeyRecord", err)
	}
	record := &SessionRecord{SessionState: NewSessionState(rs.CurrentSession)}
	for _, s := range rs.PreviousSessions {
		record.PreviousStates = append(record.PreviousStates, NewSessionState(s))
	}
	return record
}

func (record *SessionRecord) Serialize() []byte {
	rs := &protobuf.RecordStructure{}
	rs.CurrentSession = record.SessionState.SS
	for _, s := range record.PreviousStates {
		rs.PreviousSessions = append(rs.PreviousSessions, s.SS)
	}
	b, err := proto.Marshal(rs)
	if err != nil {
		log.Fatal("Cannot marshal SessionRecord", err)
	}
	return b
}

func (record *SessionRecord) HasSessionState(version uint32, key []byte) bool {
	if record.SessionState.GetSessionVersion() == version &&
		bytes.Equal(key, record.SessionState.GetAliceBaseKey()) {
		return true
	}
	for _, ss := range record.PreviousStates {
		if ss.GetSessionVersion() == version &&
			bytes.Equal(key, ss.GetAliceBaseKey()) {
			return true
		}
	}
	return false
}

func (record *SessionRecord) PromoteState(promotedState *SessionState) {
	record.PreviousStates = append([]*SessionState{record.SessionState}, record.PreviousStates...)
	if len(record.PreviousStates) > 40 {
		record.PreviousStates = record.PreviousStates[:len(record.PreviousStates)-1]
	}
	record.SessionState = promotedState
}

func (record *SessionRecord) ArchiveCurrentState() {
	record.PromoteState(NewSessionState(&protobuf.SessionStructure{}))
}

// SessionBuilder takes care of creating the sessions

type SessionBuilder struct {
	identityStore     IdentityStore
	preKeyStore       PreKeyStore
	signedPreKeyStore SignedPreKeyStore
	sessionStore      SessionStore
	recipientId       string
	deviceId          uint32
}

func NewSessionBuilder(identityStore IdentityStore, preKeyStore PreKeyStore, signedPreKeyStore SignedPreKeyStore, sessionStore SessionStore, recId string, devId uint32) *SessionBuilder {
	return &SessionBuilder{
		identityStore:     identityStore,
		preKeyStore:       preKeyStore,
		signedPreKeyStore: signedPreKeyStore,
		sessionStore:      sessionStore,
		recipientId:       recId,
		deviceId:          devId,
	}
}

func notTrusted(id string) {
	log.Printf("Identity of remote %s is not trusted, it may have reinstalled\n. For now delete the file .storage/identity/remote_%s to approve.\n", id, id)
}

var NotTrustedError = errors.New("Remote identity not trusted")

func (sb *SessionBuilder) BuildReceiverSession(sr *SessionRecord, pkwm *PreKeyWhisperMessage) (uint32, error) {
	if pkwm.Version != currentVersion {
		return 0, fmt.Errorf("Unsupported version", pkwm.Version)
	}
	theirIdentityKey := pkwm.IdentityKey
	if !sb.identityStore.IsTrustedIdentity(sb.recipientId, theirIdentityKey) {
		notTrusted(sb.recipientId)
		return 0, NotTrustedError
	}
	if sr.HasSessionState(uint32(pkwm.Version), pkwm.BaseKey.Serialize()) {
		return 0, nil
	}
	ourSignedPreKey, _ := sb.signedPreKeyStore.LoadSignedPreKey(pkwm.SignedPreKeyId)
	bob := BobAxolotlParameters{
		TheirBaseKey:    pkwm.BaseKey,
		TheirIdentity:   pkwm.IdentityKey,
		OurIdentityKey:  sb.identityStore.GetIdentityKeyPair(),
		OurSignedPreKey: ourSignedPreKey.GetKeyPair(),
		OurRatchetKey:   ourSignedPreKey.GetKeyPair(),
	}
	if pkwm.PreKeyId != 0 {
		pk, err := sb.preKeyStore.LoadPreKey(pkwm.PreKeyId)
		if err != nil {
			return 0, fmt.Errorf("key not found ", pkwm.PreKeyId)
		}
		bob.OurOneTimePreKey = pk.GetKeyPair()
	}
	if !sr.Fresh {
		sr.ArchiveCurrentState()
	}
	err := InitializeReceiverSession(sr.SessionState, pkwm.Version, bob)
	if err != nil {
		return 0, err
	}

	sr.SessionState.SetLocalRegistrationId(sb.identityStore.GetLocalRegistrationId())
	sr.SessionState.SetRemoteRegistrationId(pkwm.RegistrationId)
	sr.SessionState.SetAliceBaseKey(pkwm.BaseKey.Serialize())

	sb.identityStore.SaveIdentity(sb.recipientId, theirIdentityKey)

	return pkwm.PreKeyId, nil
}

func (sb *SessionBuilder) BuildSenderSession(pkb *PreKeyBundle) error {
	theirIdentityKey := pkb.IdentityKey
	if !sb.identityStore.IsTrustedIdentity(sb.recipientId, theirIdentityKey) {
		notTrusted(sb.recipientId)
		return NotTrustedError
	}
	if pkb.SignedPreKeyPublic != nil &&
		!curve25519sign.Verify(*theirIdentityKey.Key(), pkb.SignedPreKeyPublic.Serialize(), &pkb.SignedPreKeySignature) {
		return errors.New("Invalid signature")
	}

	sr := sb.sessionStore.LoadSession(sb.recipientId, sb.deviceId)
	ourBaseKey := NewECKeyPair()
	theirSignedPreKey := pkb.SignedPreKeyPublic
	theirOneTimePreKey := pkb.PreKeyPublic
	theirOneTimePreKeyId := pkb.PreKeyId

	alice := AliceAxolotlParameters{
		OurBaseKey:         ourBaseKey,
		OurIdentityKey:     sb.identityStore.GetIdentityKeyPair(),
		TheirIdentity:      pkb.IdentityKey,
		TheirSignedPreKey:  theirSignedPreKey,
		TheirRatchetKey:    theirSignedPreKey,
		TheirOneTimePreKey: theirOneTimePreKey,
	}

	if !sr.Fresh {
		sr.ArchiveCurrentState()
	}

	err := InitializeSenderSession(sr.SessionState, 3, alice)
	if err != nil {
		return err
	}

	sr.SessionState.SetUnacknowledgedPreKeyMessage(theirOneTimePreKeyId, pkb.SignedPreKeyId, &ourBaseKey.PublicKey)
	sr.SessionState.SetLocalRegistrationId(sb.identityStore.GetLocalRegistrationId())
	sr.SessionState.SetRemoteRegistrationId(pkb.RegistrationId)
	sr.SessionState.SetAliceBaseKey(ourBaseKey.PublicKey.Serialize())

	sb.sessionStore.StoreSession(sb.recipientId, sb.deviceId, sr)
	sb.identityStore.SaveIdentity(sb.recipientId, theirIdentityKey)
	return nil
}

type SessionCipher struct {
	RecipientId  string
	DeviceId     uint32
	SessionStore SessionStore
	PreKeyStore  PreKeyStore
	Builder      *SessionBuilder
}

func NewSessionCipher(identityStore IdentityStore, preKeyStore PreKeyStore, signedPreKeyStore SignedPreKeyStore, sessionStore SessionStore, recId string, devId uint32) *SessionCipher {
	return &SessionCipher{
		RecipientId:  recId,
		DeviceId:     devId,
		SessionStore: sessionStore,
		PreKeyStore:  preKeyStore,
		Builder:      NewSessionBuilder(identityStore, preKeyStore, signedPreKeyStore, sessionStore, recId, devId),
	}
}

func (sc *SessionCipher) SessionEncryptMessage(plaintext []byte) ([]byte, int32, error) {
	sr := sc.SessionStore.LoadSession(sc.RecipientId, sc.DeviceId)
	ss := sr.SessionState
	chainKey := ss.GetSenderChainKey()
	messageKeys, err := chainKey.GetMessageKeys()
	if err != nil {
		return nil, 0, err
	}
	senderEphemeral := ss.GetSenderRatchetKey()
	previousCounter := ss.GetPreviousCounter()
	ciphertext := Encrypt(messageKeys.CipherKey, messageKeys.Iv, plaintext)
	version := ss.GetSessionVersion()

	wm, err := NewWhisperMessage(byte(version), messageKeys.MacKey, senderEphemeral, chainKey.Index,
		previousCounter, ciphertext, ss.GetLocalIdentityPublic(), ss.GetRemoteIdentityPublic())
	if err != nil {
		return nil, 0, err
	}
	msg := wm.Serialize()
	msgType := int32(1) // textsecure.IncomingPushMessageSignal_CIPHERTEXT

	if ss.HasUnacknowledgedPreKeyMessage() {
		items := ss.GetUnacknowledgedPreKeyMessageItems()
		pkwm, err := NewPreKeyWhisperMessage(byte(version), ss.GetLocalRegistrationId(),
			items.preKeyId, uint32(items.signedPreKeyId), items.baseKey,
			ss.GetLocalIdentityPublic(), wm)
		if err != nil {
			return nil, 0, nil
		}
		msg = pkwm.Serialize()
		msgType = int32(3) // textsecure.IncomingPushMessageSignal_PREKEY_BUNDLE
	}

	ss.SetSenderChainKey(chainKey.GetNextChainKey())
	sc.SessionStore.StoreSession(sc.RecipientId, sc.DeviceId, sr)

	return msg, msgType, nil
}

func (sc *SessionCipher) GetRemoteRegistrationId() uint32 {
	sr := sc.SessionStore.LoadSession(sc.RecipientId, sc.DeviceId)
	return sr.SessionState.GetRemoteRegistrationId()
}

func (sc *SessionCipher) decrypt(sr *SessionRecord, ciphertext *WhisperMessage) ([]byte, error) {
	ss := sr.SessionState
	if !ss.HasSenderChain() {
		return nil, errors.New("Uninitialized session")
	}
	if uint32(ciphertext.Version) != ss.GetSessionVersion() {
		return nil, fmt.Errorf("Cipher version %d does not match session version %d", ciphertext.Version, ss.GetSessionVersion())
	}

	theirEphemeral := ciphertext.RatchetKey
	counter := ciphertext.Counter
	chainKey, err := GetOrCreateChainKey(ss, theirEphemeral)
	if err != nil {
		return nil, err
	}
	messageKeys, err := GetOrCreateMessageKeys(ss, theirEphemeral, chainKey, counter)
	if err != nil {
		return nil, err
	}

	ciphertext.VerifyMAC(ss.GetRemoteIdentityPublic(), ss.GetLocalIdentityPublic(), messageKeys.MacKey)

	plaintext := Decrypt(messageKeys.CipherKey, append(messageKeys.Iv, ciphertext.Ciphertext...))

	ss.ClearUnacknowledgedPreKeyMessage()

	return plaintext, nil
}

func (sc *SessionCipher) SessionDecryptWhisperMessage(ciphertext *WhisperMessage) ([]byte, error) {
	sr := sc.SessionStore.LoadSession(sc.RecipientId, sc.DeviceId)
	plaintext, err := sc.decrypt(sr, ciphertext)
	if err != nil {
		return nil, err
	}
	sc.SessionStore.StoreSession(sc.RecipientId, sc.DeviceId, sr)
	return plaintext, nil
}

func (sc *SessionCipher) SessionDecryptPreKeyWhisperMessage(ciphertext *PreKeyWhisperMessage) ([]byte, error) {
	sr := sc.SessionStore.LoadSession(sc.RecipientId, sc.DeviceId)
	pkid, err := sc.Builder.BuildReceiverSession(sr, ciphertext)
	if err != nil {
		return nil, err
	}
	plaintext, err := sc.decrypt(sr, ciphertext.Message)
	if err != nil {
		return nil, err
	}
	if pkid != 0 {
		sc.PreKeyStore.RemovePreKey(pkid)
	}
	sc.SessionStore.StoreSession(sc.RecipientId, sc.DeviceId, sr)
	return plaintext, nil
}

func GetOrCreateChainKey(ss *SessionState, theirEphemeral *ECPublicKey) (*ChainKey, error) {
	if ss.HasReceiverChain(theirEphemeral) {
		return ss.GetReceiverChainKey(theirEphemeral), nil
	}

	rootKey := ss.GetRootKey()
	ourEphemeral := ss.GetSenderRatchetKeyPair()
	receiverChain, err := rootKey.CreateChain(theirEphemeral, ourEphemeral)
	if err != nil {
		return nil, err
	}

	ourNewEphemeral := NewECKeyPair()
	senderChain, err := receiverChain.RootKey.CreateChain(theirEphemeral, ourNewEphemeral)
	if err != nil {
		return nil, err
	}

	ss.SetRootKey(&senderChain.RootKey)
	ss.AddReceiverChain(theirEphemeral, &receiverChain.ChainKey)
	pc := ss.GetSenderChainKey().Index
	if pc > 0 {
		pc--
	}
	ss.SetPreviousCounter(pc)
	ss.SetSenderChain(ourNewEphemeral, &senderChain.ChainKey)
	return &receiverChain.ChainKey, nil
}

func GetOrCreateMessageKeys(ss *SessionState, theirEphemeral *ECPublicKey, chainKey *ChainKey, counter uint32) (*MessageKeys, error) {
	if chainKey.Index > counter {
		if ss.HasMessageKeys(theirEphemeral, counter) {
			return ss.RemoveMessageKeys(theirEphemeral, counter), nil
		} else {
			return nil, fmt.Errorf("Duplicate message: expected %d, got %d", chainKey.Index, counter)
		}
	}
	if int(counter)-int(chainKey.Index) > 2000 {
		return nil, errors.New("Over 2000 messages in the future")
	}
	for chainKey.Index < counter {
		messageKeys, err := chainKey.GetMessageKeys()
		if err != nil {
			return nil, err
		}
		ss.SetMessageKeys(theirEphemeral, messageKeys)
		chainKey = chainKey.GetNextChainKey()
	}

	ss.SetReceiverChainKey(theirEphemeral, chainKey.GetNextChainKey())
	return chainKey.GetMessageKeys()
}
