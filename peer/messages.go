// Package peer defines the P2P protocol spoken directly between
// Client-Nodes that share a secret — the layer the orchestrator never
// sees. Where protocol.OrchestratorClient carries pseudonyms and routing,
// this layer carries the real grouping (which pseudo-IDs together
// reconstruct which secret) and is authenticated by a per-group token
// established only among the cooperating peers at split time.
//
// In production the transport under this would be mutually authenticated
// (device-attested mTLS) rather than the plain localhost HTTP used here
// for the demo — that swap doesn't change any message shape below.
package peer

// Member describes one sibling holder of a share in the same group.
type Member struct {
	PID      string `json:"pid"`
	NodeID   string `json:"node_id"`
	Endpoint string `json:"endpoint"`
}

// DeliverShareRequest is pushed by the owning node to each peer at split
// time: "here is your share of group G, and here is who your siblings
// are." GroupToken is the shared secret that lets this group's members
// recognize each other on later calls without the orchestrator's help.
//
// Key is the one point in the whole system where a symmetric key
// legitimately crosses the wire: handing a peer custody of a share means
// handing it the ability to decrypt/re-encrypt it. In production this
// call is over a mutually-attested, encrypted channel; the demo sends it
// over plain localhost HTTP. The instant the receiving node accepts
// custody it re-seals Key under its own hardware-bound storage key
// (store.PutFragment) and independently starts its own ratchet and its
// own cold-mutation hash chain — the sender has no further say over it.
type DeliverShareRequest struct {
	GroupID    string   `json:"group_id"`
	GroupToken string   `json:"group_token"`
	PID        string   `json:"pid"`
	Epoch      uint64   `json:"epoch"`
	Threshold  int      `json:"threshold"`
	Total      int      `json:"total"`
	Key        []byte   `json:"key"` // one-time custody handoff; see doc comment below
	Ciphertext []byte   `json:"ciphertext"`
	Members    []Member `json:"members"`
}

// MutationNoticeRequest is peer-to-peer gossip: "my pseudonym for group G
// changed from OldPID to NewPID, now served at NewEndpoint." This is how
// the group's map stays in sync without the orchestrator ever learning
// that OldPID and NewPID belong to the same secret.
type MutationNoticeRequest struct {
	GroupID    string `json:"group_id"`
	GroupToken string `json:"group_token"`
	OldPID     string `json:"old_pid"`
	NewPID     string `json:"new_pid"`
	NewEndpoint string `json:"new_endpoint"`
	Epoch      uint64 `json:"epoch"`
}

// PresenceResponse answers a status check without ever decrypting or
// revealing the share itself — used by SelfHeal to count live holders
// cheaply, reserving the actual (more expensive, more sensitive) fetch
// for when a re-share is genuinely needed.
type PresenceResponse struct {
	Present bool   `json:"present"`
	Epoch   uint64 `json:"epoch"`
}

// ShareResponse answers a fetch during reconstruction with the already
// decrypted Shamir share (see peer.Client.FetchGroupShare for why the key
// itself never needs to cross the wire here: possession of GroupToken is
// what authorizes seeing this one share's plaintext).
type ShareResponse struct {
	Share []byte `json:"share"`
	Epoch uint64 `json:"epoch"`
}
