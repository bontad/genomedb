// Package protocol defines the wire messages exchanged between the
// Server-Orchestrator and Client-Nodes, and the client-side helper to
// speak it. Every message here is deliberately thin: pseudonyms,
// endpoints, epochs and random seeds — never fragment content, never a
// derived key, never the grouping of pseudo-IDs into a real secret (that
// last piece is P2P-only knowledge, see peer/*).
package protocol

import "time"

// Heartbeat is sent Client -> Server on a regular cadence. por_proof is a
// stand-in for a proof-of-retrievability challenge response (a real
// implementation proves possession of the ciphertext without sending it,
// e.g. a keyed hash over a server-chosen byte range); here it's a hash of
// the local ciphertext, which is enough to demonstrate the shape of the
// check without a full PoR scheme.
type Heartbeat struct {
	NodeID    string `json:"node_id"`
	PID       string `json:"pid"`
	Epoch     uint64 `json:"epoch"`
	RiskScore int    `json:"risk_score"`
	PorProof  string `json:"por_proof"`
}

// MutationSeed is pushed Server -> Client to advance one fragment's
// ratchet. Seed is pure randomness the orchestrator generated; it is
// mixed with local entropy client-side and never suffices on its own to
// derive a key (see crypto.Advance).
type MutationSeed struct {
	PID    string `json:"pid"`
	Seed   []byte `json:"seed"`
	Reason string `json:"reason"` // "scheduled" | "operator"
	Epoch  uint64 `json:"epoch"`
}

// MutationAck is the Client -> Server confirmation that a mutation
// completed. Commitment is a hash the server can log for audit but cannot
// invert to recover the new key.
//
// For a scheduled mutation the server already generated Seed itself, so
// there's nothing to verify. For a "cold" mutation (triggered locally by
// the watchdog, completed before any network round trip) the client
// reveals SeedUsed — one link of its pre-provisioned hash chain — so the
// orchestrator can verify it after the fact against the chain's last
// trusted anchor (crypto.VerifyStep) without ever having been online at
// the moment of the incident.
type MutationAck struct {
	NodeID     string `json:"node_id"`
	OldPID     string `json:"old_pid"`
	NewPID     string `json:"new_pid"`
	Epoch      uint64 `json:"epoch"`
	Commitment string `json:"commitment"`
	Reason     string `json:"reason"` // "scheduled" | "cold"
	ChainID    string `json:"chain_id,omitempty"`
	SeedUsed   []byte `json:"seed_used,omitempty"`
}

// RouteEntry is one row of the orchestrator's blind routing table: it
// says which endpoint currently answers for a pseudonym, nothing more.
// ChainID identifies (without revealing) the pre-provisioned hash chain
// backing this fragment's offline "cold" mutation path — see
// crypto.BuildChain.
type RouteEntry struct {
	PID      string `json:"pid"`
	NodeID   string `json:"node_id"`
	Endpoint string `json:"endpoint"`
	Epoch    uint64 `json:"epoch"`
	ChainID  string `json:"chain_id"`
}

// MapDelta is gossiped Server -> Clients: an incremental batch of route
// changes, never a full-state broadcast.
type MapDelta struct {
	Epoch   uint64       `json:"epoch"`
	Changes []RouteEntry `json:"changes"`
}

// ImmuneAlert is the coarse, rate-limited Client -> Server signal that a
// local mutation happened because the watchdog fired, not on schedule.
// Deliberately carries no forensic detail.
type ImmuneAlert struct {
	NodeID   string    `json:"node_id"`
	PID      string    `json:"pid"`
	Severity string    `json:"severity"` // "suspect" | "confirmed"
	At       time.Time `json:"at"`
}

// RouteAnnounce is sent Client -> Server the first time a pseudo-ID comes
// into existence (i.e. right after a fresh split, never as part of a
// mutation — mutations go through MutationAck instead). It's how a brand
// new blind routing entry enters the orchestrator's table. ChainTip is
// the tip of the fragment's freshly built cold-mutation hash chain
// (chain[length] from crypto.BuildChain) — the trusted anchor the
// orchestrator will later verify the first cold mutation against.
type RouteAnnounce struct {
	NodeID   string `json:"node_id"`
	PID      string `json:"pid"`
	Endpoint string `json:"endpoint"`
	ChainID  string `json:"chain_id"`
	ChainTip []byte `json:"chain_tip"`
}

// RegisterRequest is sent once by a client daemon on startup.
type RegisterRequest struct {
	NodeID   string `json:"node_id"`
	Endpoint string `json:"endpoint"` // where this node's peer server listens
}

// RegisterResponse acknowledges registration.
type RegisterResponse struct {
	OK bool `json:"ok"`
}

// NodeInfo is a public directory entry: which endpoint answers for a
// node_id. Endpoints alone aren't sensitive; the sensitive part (which
// pids/groups a node holds) never appears here.
type NodeInfo struct {
	NodeID   string `json:"node_id"`
	Endpoint string `json:"endpoint"`
}
