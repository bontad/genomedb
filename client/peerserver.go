package client

import (
	"crypto/subtle"
	"encoding/json"
	"log"
	"net/http"

	mcrypto "mutant-db/crypto"
	"mutant-db/peer"
	"mutant-db/store"
)

// PeerMux is the HTTP surface a node exposes to its siblings — the P2P
// layer the orchestrator never sees or touches.
func (n *Node) PeerMux() *http.ServeMux {
	mux := http.NewServeMux()

	mux.HandleFunc("POST /peer/deliver", func(w http.ResponseWriter, r *http.Request) {
		var req peer.DeliverShareRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		chainID, err := randomID(8)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if _, err := n.registerNewFragment(req.PID, chainID); err != nil {
			http.Error(w, "registrazione rotta fallita: "+err.Error(), http.StatusInternalServerError)
			return
		}
		members := make([]store.Member, len(req.Members))
		for i, m := range req.Members {
			members[i] = store.Member{PID: m.PID, NodeID: m.NodeID, Endpoint: m.Endpoint}
		}
		if err := n.store.PutFragment(store.Fragment{
			PID: req.PID, GroupID: req.GroupID, GroupToken: req.GroupToken, ChainID: chainID,
			Epoch: req.Epoch, Threshold: req.Threshold, Total: req.Total,
			Key: req.Key, Ciphertext: req.Ciphertext, Members: members,
		}); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		log.Printf("[%s] custodia ricevuta: pid=%s gruppo=%s (soglia %d/%d)", n.NodeID, req.PID, req.GroupID, req.Threshold, req.Total)
		w.WriteHeader(http.StatusNoContent)
	})

	mux.HandleFunc("GET /peer/ping", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	mux.HandleFunc("GET /peer/group/{group_id}/status", func(w http.ResponseWriter, r *http.Request) {
		groupID := r.PathValue("group_id")
		token := r.Header.Get("X-Group-Token")
		frag, err := n.store.GetFragmentByGroup(groupID)
		if err != nil {
			http.Error(w, "gruppo sconosciuto", http.StatusNotFound)
			return
		}
		if subtle.ConstantTimeCompare([]byte(token), []byte(frag.GroupToken)) != 1 {
			http.Error(w, "token di gruppo non valido", http.StatusForbidden)
			return
		}
		json.NewEncoder(w).Encode(peer.PresenceResponse{Present: true, Epoch: frag.Epoch})
	})

	mux.HandleFunc("GET /peer/group/{group_id}", func(w http.ResponseWriter, r *http.Request) {
		groupID := r.PathValue("group_id")
		token := r.Header.Get("X-Group-Token")

		frag, err := n.store.GetFragmentByGroup(groupID)
		if err != nil {
			http.Error(w, "gruppo sconosciuto", http.StatusNotFound)
			return
		}
		if subtle.ConstantTimeCompare([]byte(token), []byte(frag.GroupToken)) != 1 {
			http.Error(w, "token di gruppo non valido", http.StatusForbidden)
			return
		}
		share, err := mcrypto.Decrypt(frag.Key, frag.Ciphertext, []byte(frag.GroupID+":"+frag.PID))
		if err != nil {
			http.Error(w, "decifratura locale fallita", http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(peer.ShareResponse{Share: share, Epoch: frag.Epoch})
		mcrypto.Wipe(share)
	})

	mux.HandleFunc("POST /peer/mutation-notice", func(w http.ResponseWriter, r *http.Request) {
		var req peer.MutationNoticeRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := n.store.UpdateSibling(req.GroupID, req.OldPID, req.NewPID, req.NewEndpoint); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if err := n.store.UpdateManifestMember(req.GroupID, req.OldPID, req.NewPID, req.NewEndpoint); err != nil && err != store.ErrNotFound {
			log.Printf("[%s] aggiornamento manifest fallito: %v", n.NodeID, err)
		}
		log.Printf("[%s] notifica di mutazione ricevuta: %s -> %s (gruppo %s)", n.NodeID, req.OldPID, req.NewPID, req.GroupID)
		w.WriteHeader(http.StatusNoContent)
	})

	return mux
}
