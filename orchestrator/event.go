package orchestrator

import (
	"encoding/json"

	"mutant-db/protocol"
)

func mustEvent(evType string, payload any) protocol.Event {
	data, err := json.Marshal(payload)
	if err != nil {
		panic(err) // payload types are all local structs with only marshalable fields
	}
	return protocol.Event{Type: evType, Data: data}
}
