package orchestrator

import (
	"encoding/json"
	"fmt"
	"net/http"

	"mutant-db/protocol"
)

// NewMux builds the orchestrator's HTTP surface. Every handler here only
// ever touches pseudonyms, endpoints and epochs — see orchestrator.go's
// package doc for why that boundary matters.
func NewMux(o *Orchestrator) *http.ServeMux {
	mux := http.NewServeMux()

	mux.HandleFunc("POST /register", func(w http.ResponseWriter, r *http.Request) {
		var req protocol.RegisterRequest
		if !decode(w, r, &req) {
			return
		}
		o.Register(req.NodeID, req.Endpoint)
		encode(w, protocol.RegisterResponse{OK: true})
	})

	mux.HandleFunc("POST /route/announce", func(w http.ResponseWriter, r *http.Request) {
		var req protocol.RouteAnnounce
		if !decode(w, r, &req) {
			return
		}
		o.AnnounceRoute(req)
		w.WriteHeader(http.StatusNoContent)
	})

	mux.HandleFunc("POST /heartbeat", func(w http.ResponseWriter, r *http.Request) {
		var hb protocol.Heartbeat
		if !decode(w, r, &hb) {
			return
		}
		o.Heartbeat(hb)
		w.WriteHeader(http.StatusNoContent)
	})

	mux.HandleFunc("POST /mutation/ack", func(w http.ResponseWriter, r *http.Request) {
		var ack protocol.MutationAck
		if !decode(w, r, &ack) {
			return
		}
		o.Ack(ack)
		w.WriteHeader(http.StatusNoContent)
	})

	mux.HandleFunc("POST /alert", func(w http.ResponseWriter, r *http.Request) {
		var a protocol.ImmuneAlert
		if !decode(w, r, &a) {
			return
		}
		if !o.Alert(a) {
			http.Error(w, "rate limited", http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})

	mux.HandleFunc("GET /map", func(w http.ResponseWriter, r *http.Request) {
		encode(w, o.Snapshot())
	})

	mux.HandleFunc("GET /nodes", func(w http.ResponseWriter, r *http.Request) {
		encode(w, o.Nodes())
	})

	mux.HandleFunc("GET /events", func(w http.ResponseWriter, r *http.Request) {
		nodeID := r.URL.Query().Get("node_id")
		if nodeID == "" {
			http.Error(w, "missing node_id", http.StatusBadRequest)
			return
		}
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming unsupported", http.StatusInternalServerError)
			return
		}
		ch, unsubscribe := o.Subscribe(nodeID)
		defer unsubscribe()

		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.WriteHeader(http.StatusOK)
		flusher.Flush()

		ctx := r.Context()
		for {
			select {
			case ev, open := <-ch:
				if !open {
					return
				}
				fmt.Fprintf(w, "event: %s\ndata: %s\n\n", ev.Type, ev.Data)
				flusher.Flush()
			case <-ctx.Done():
				return
			}
		}
	})

	return mux
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
		return false
	}
	return true
}

func encode(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}
