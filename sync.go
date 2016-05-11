package textsecure

import (
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"os"

	log "github.com/Sirupsen/logrus"
	"github.com/golang/protobuf/proto"
	"github.com/janimo/textsecure/protobuf"
)

// handleSyncMessage handles an incoming SyncMessage.
func handleSyncMessage(src string, timestamp uint64, sm *textsecure.SyncMessage) error {
	log.Debugf("SyncMessage recieved at %d", timestamp)
	if !config.EnableMultiDeviceSync {
		log.Debugf("Multi-Device sync is disabled. Ignoring message")
		return nil
	}

	if sm.GetSent() != nil {
		return handleSyncSent(sm.GetSent())
	} else if sm.GetRequest() != nil {
		return handleSyncRequest(sm.GetRequest())
	} else if sm.GetRead() != nil {
		return handleSyncRead(sm.GetRead())
	} else {
		log.Errorf("SyncMessage contains no known sync types")
	}

	return nil
}

// handleSyncSent handles sync sent messages
func handleSyncSent(s *textsecure.SyncMessage_Sent) error {
	dm := s.GetMessage()
	dest := s.GetDestination()
	timestamp := s.GetTimestamp()

	if dm == nil {
		return fmt.Errorf("DataMessage was nil for SyncMessage_Sent")
	}

	flags, err := handleFlags(dest, dm)
	if err != nil {
		return err
	}

	atts, err := handleAttachments(dm)
	if err != nil {
		return err
	}

	gr, err := handleGroups(dest, dm)
	if err != nil {
		return err
	}

	msg := &Message{
		source:      dest,
		message:     dm.GetBody(),
		attachments: atts,
		group:       gr,
		timestamp:   timestamp,
		flags:       flags,
	}

	if client.SyncSentHandler != nil {
		client.SyncSentHandler(msg)
	}

	return nil
}

// handleSyncRequestMessage
func handleSyncRequest(request *textsecure.SyncMessage_Request) error {
	if request.GetType() == textsecure.SyncMessage_Request_CONTACTS {
		return sendContactUpdate()
	} else if request.GetType() == textsecure.SyncMessage_Request_GROUPS {
		return sendGroupUpdate()
	}

	return nil
}

// sendContactUpdate
func sendContactUpdate() error {
	log.Debugf("Sending contact SyncMessage")

	lc, err := GetRegisteredContacts()
	if err != nil {
		return fmt.Errorf("could not get local contacts: %s", err)
	}

	tmp, err := ioutil.TempFile(config.StorageDir, "multidevice-contact-update")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())

	for _, c := range lc {
		cd := &textsecure.ContactDetails{
			Number: &c.Tel,
			Name:   &c.Name,
			// TODO: handle avatars
		}

		b, err := proto.Marshal(cd)
		if err != nil {
			log.Errorf("Failed to marshal contact details")
			continue
		}

		tmp.Write(varint32(len(b)))
		tmp.Write(b)
	}

	tmp.Sync()
	tmp.Seek(0, 0)

	a, err := uploadAttachment(tmp, "application/octet-stream")
	if err != nil {
		return err
	}

	sm := &textsecure.SyncMessage{
		Contacts: &textsecure.SyncMessage_Contacts{
			Blob: &textsecure.AttachmentPointer{
				Id:          &a.id,
				ContentType: &a.ct,
				Key:         a.keys,
			},
		},
	}

	_, err = sendSyncMessage(sm)
	return err
}

// sendGroupUpdate
func sendGroupUpdate() error {
	log.Debugf("Sending group SyncMessage")

	tmp, err := ioutil.TempFile(config.StorageDir, "multidevice-group-update")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())

	for _, g := range groups {
		gd := &textsecure.GroupDetails{
			Id:      g.ID,
			Name:    &g.Name,
			Members: g.Members,
			// XXX add support for avatar
			// XXX add support for active?
		}

		b, err := proto.Marshal(gd)
		if err != nil {
			log.Errorf("Failed to marshal group details")
			continue
		}

		tmp.Write(varint32(len(b)))
		tmp.Write(b)
	}

	tmp.Sync()
	tmp.Seek(0, 0)

	a, err := uploadAttachment(tmp, "application/octet-stream")
	if err != nil {
		return err
	}

	sm := &textsecure.SyncMessage{
		Groups: &textsecure.SyncMessage_Groups{
			Blob: &textsecure.AttachmentPointer{
				Id:          &a.id,
				ContentType: &a.ct,
				Key:         a.keys,
			},
		},
	}

	_, err = sendSyncMessage(sm)
	return err
}

func handleSyncRead(readMessages []*textsecure.SyncMessage_Read) error {
	if client.SyncReadHandler != nil {
		for _, s := range readMessages {
			client.SyncReadHandler(s.GetSender(), s.GetTimestamp())
		}
	}

	return nil
}

// Encodes a 32bit base 128 variable-length integer and returns the bytes
func varint32(value int) []byte {
	buf := make([]byte, binary.MaxVarintLen32)
	n := binary.PutUvarint(buf, uint64(value))
	return buf[:n]
}
