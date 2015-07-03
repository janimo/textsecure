package textsecure

import (
	log "github.com/Sirupsen/logrus"
	"github.com/janimo/textsecure/protobuf"
)

// handleSyncMessage handles an incoming SyncMessage
func handleSyncMessage(src string, timestamp uint64, sm *textsecure.SyncMessage) error {
	log.Debugf("SyncMessage is %+v\n", sm)
	return nil
}
