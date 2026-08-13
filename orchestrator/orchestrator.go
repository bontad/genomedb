// Package orchestrator implements the Server-Orchestrator: it holds a
// blind routing table (pseudo-ID -> endpoint), hands out random mutation
// seeds, and gossips small deltas — and never anything else. It has no
// concept of "secret", "group", "share content" or "key"; those never
// appear in this package.
package orchestrator

import (
	"crypto/rand"
	"log"
	"math/big"
	"sync"
	"time"

	mcrypto "mutant-db/crypto"
	"mutant-db/protocol"
)

type nodeInfo struct {
	Endpoint string
	LastSeen time.Time
}

type Orchestrator struct {
	mu     sync.Mutex
	nodes  map[string]nodeInfo
	routes map[string]protocol.RouteEntry // pid -> entry
	epoch  uint64

	subs map[string]chan protocol.Event // node_id -> subscriber channel

	alertBucket  map[string]time.Time // node_id -> last accepted alert, for rate limiting
	chainAnchors map[string][]byte    // chain_id -> last-trusted hash-chain link, for cold-mutation verification

	MutationInterval time.Duration
	MutationJitter   time.Duration
}

func New() *Orchestrator {
	return &Orchestrator{
		nodes:            make(map[string]nodeInfo),
		routes:           make(map[string]protocol.RouteEntry),
		subs:             make(map[string]chan protocol.Event),
		alertBucket:      make(map[string]time.Time),
		chainAnchors:     make(map[string][]byte),
		MutationInterval: 20 * time.Second,
		MutationJitter:   15 * time.Second,
	}
}

func (o *Orchestrator) Register(nodeID, endpoint string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.nodes[nodeID] = nodeInfo{Endpoint: endpoint, LastSeen: time.Now()}
	log.Printf("[orchestrator] nodo registrato: %s @ %s", nodeID, endpoint)
}

func (o *Orchestrator) Heartbeat(hb protocol.Heartbeat) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if n, ok := o.nodes[hb.NodeID]; ok {
		n.LastSeen = time.Now()
		o.nodes[hb.NodeID] = n
	}
}

// AnnounceRoute registers a brand-new pseudo-ID (post-split, epoch 0) and
// the trusted anchor for its cold-mutation hash chain.
func (o *Orchestrator) AnnounceRoute(a protocol.RouteAnnounce) {
	o.mu.Lock()
	entry := protocol.RouteEntry{PID: a.PID, NodeID: a.NodeID, Endpoint: a.Endpoint, Epoch: 0, ChainID: a.ChainID}
	o.routes[a.PID] = entry
	o.chainAnchors[a.ChainID] = a.ChainTip
	o.mu.Unlock()
	o.broadcastDelta([]protocol.RouteEntry{entry})
	log.Printf("[orchestrator] nuova rotta: pid=%s node=%s chain=%s", a.PID, a.NodeID, a.ChainID)
}

// Ack applies a completed mutation to the routing table and gossips the
// single changed entry — never a full-state broadcast. For a "cold"
// mutation it also verifies (after the fact) that the revealed seed is a
// genuine, un-guessable step of the announced hash chain.
func (o *Orchestrator) Ack(ack protocol.MutationAck) {
	if ack.Reason == "cold" {
		o.mu.Lock()
		anchor, known := o.chainAnchors[ack.ChainID]
		o.mu.Unlock()
		if !known {
			log.Printf("[orchestrator] ATTENZIONE: ack a freddo per chain sconosciuta %s (nodo %s)", ack.ChainID, ack.NodeID)
		} else if !mcrypto.VerifyStep(ack.SeedUsed, anchor) {
			log.Printf("[orchestrator] ATTENZIONE: verifica hash-chain FALLITA per %s — seed rivelato non discende dall'ancora nota", ack.ChainID)
		} else {
			log.Printf("[orchestrator] verifica hash-chain OK per %s (mutazione a freddo confermata a posteriori)", ack.ChainID)
			o.mu.Lock()
			o.chainAnchors[ack.ChainID] = ack.SeedUsed
			o.mu.Unlock()
		}
	}

	o.mu.Lock()
	old, ok := o.routes[ack.OldPID]
	endpoint := ack.NodeID
	if ok {
		endpoint = old.Endpoint
	}
	delete(o.routes, ack.OldPID)
	entry := protocol.RouteEntry{PID: ack.NewPID, NodeID: ack.NodeID, Endpoint: endpoint, Epoch: ack.Epoch, ChainID: ack.ChainID}
	o.routes[ack.NewPID] = entry
	o.mu.Unlock()

	o.broadcastDelta([]protocol.RouteEntry{entry})
	log.Printf("[orchestrator] mutazione confermata (%s): %s -> %s (epoch %d, commit %s)", ack.Reason, ack.OldPID, ack.NewPID, ack.Epoch, ack.Commitment)
}

// Alert accepts a throttled immune-system signal — at most one per node
// every 3s, to keep a compromised or noisy node from turning its own
// alert channel into a denial-of-service vector against the control plane.
func (o *Orchestrator) Alert(a protocol.ImmuneAlert) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	last, ok := o.alertBucket[a.NodeID]
	if ok && time.Since(last) < 3*time.Second {
		return false
	}
	o.alertBucket[a.NodeID] = time.Now()
	log.Printf("[orchestrator] IMMUNE_ALERT node=%s pid=%s severity=%s", a.NodeID, a.PID, a.Severity)
	return true
}

// Nodes lists registered node endpoints — used for peer discovery when
// splitting a new secret. Endpoints aren't sensitive on their own (unlike
// the pid groupings), so sharing the full registry is fine.
func (o *Orchestrator) Nodes() []protocol.NodeInfo {
	o.mu.Lock()
	defer o.mu.Unlock()
	out := make([]protocol.NodeInfo, 0, len(o.nodes))
	for id, n := range o.nodes {
		out = append(out, protocol.NodeInfo{NodeID: id, Endpoint: n.Endpoint})
	}
	return out
}

func (o *Orchestrator) Snapshot() []protocol.RouteEntry {
	o.mu.Lock()
	defer o.mu.Unlock()
	out := make([]protocol.RouteEntry, 0, len(o.routes))
	for _, e := range o.routes {
		out = append(out, e)
	}
	return out
}

// Subscribe registers an SSE channel for a node and returns it plus an
// unsubscribe func.
func (o *Orchestrator) Subscribe(nodeID string) (chan protocol.Event, func()) {
	ch := make(chan protocol.Event, 16)
	o.mu.Lock()
	o.subs[nodeID] = ch
	o.mu.Unlock()
	return ch, func() {
		o.mu.Lock()
		delete(o.subs, nodeID)
		o.mu.Unlock()
		close(ch)
	}
}

func (o *Orchestrator) broadcastDelta(changes []protocol.RouteEntry) {
	o.mu.Lock()
	o.epoch++
	delta := protocol.MapDelta{Epoch: o.epoch, Changes: changes}
	subs := make([]chan protocol.Event, 0, len(o.subs))
	for _, ch := range o.subs {
		subs = append(subs, ch)
	}
	o.mu.Unlock()

	ev := mustEvent("map_delta", delta)
	for _, ch := range subs {
		select {
		case ch <- ev:
		default: // slow subscriber: drop rather than block the control plane
		}
	}
}

func (o *Orchestrator) pushSeed(nodeID string, seed protocol.MutationSeed) {
	o.mu.Lock()
	ch, ok := o.subs[nodeID]
	o.mu.Unlock()
	if !ok {
		return
	}
	ev := mustEvent("mutation_seed", seed)
	select {
	case ch <- ev:
	default:
	}
}

// RunScheduledMutations periodically picks one random live route and
// pushes it a fresh mutation seed, jittered so the cadence itself isn't a
// predictable, observable pattern. It runs until ctxDone is closed.
func (o *Orchestrator) RunScheduledMutations(ctxDone <-chan struct{}) {
	for {
		wait := o.MutationInterval + jitter(o.MutationJitter)
		select {
		case <-time.After(wait):
		case <-ctxDone:
			return
		}
		o.mu.Lock()
		var candidates []protocol.RouteEntry
		for _, e := range o.routes {
			candidates = append(candidates, e)
		}
		o.mu.Unlock()
		if len(candidates) == 0 {
			continue
		}
		idx, err := randInt(len(candidates))
		if err != nil {
			continue
		}
		target := candidates[idx]
		seed := make([]byte, 32)
		if _, err := rand.Read(seed); err != nil {
			continue
		}
		log.Printf("[orchestrator] mutazione pianificata -> pid=%s node=%s", target.PID, target.NodeID)
		o.pushSeed(target.NodeID, protocol.MutationSeed{
			PID: target.PID, Seed: seed, Reason: "scheduled", Epoch: target.Epoch + 1,
		})
	}
}

func jitter(max time.Duration) time.Duration {
	if max <= 0 {
		return 0
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		return 0
	}
	return time.Duration(n.Int64())
}

func randInt(n int) (int, error) {
	b, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		return 0, err
	}
	return int(b.Int64()), nil
}
