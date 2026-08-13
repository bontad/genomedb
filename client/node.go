// Package client implements the Client-Node daemon: it holds shares on
// behalf of the user, drives the mutation ratchet (both scheduled and
// watchdog-triggered), and speaks both protocols — protocol.* to the
// orchestrator and peer.* to sibling nodes.
package client

import (
	"context"
	"crypto/rand"
	"fmt"
	"log"
	"os"
	"sync"

	mcrypto "mutant-db/crypto"
	"mutant-db/peer"
	"mutant-db/protocol"
	"mutant-db/store"
)

const coldChainLength = 64 // pre-provisioned offline mutations before re-provisioning is needed

// ColdChain is the in-memory hash-chain state backing one fragment's
// offline mutation capability. It is never written to disk in this demo;
// a production node would reseal it the same way it seals the root key
// (crypto.LoadOrCreateRoot) so a restart doesn't lose remaining links.
type ColdChain struct {
	Chain [][]byte
	Next  int // index of the next link to reveal; counts down to 0
}

func (c *ColdChain) Consume() ([]byte, bool) {
	if c.Next < 0 {
		return nil, false
	}
	seed := c.Chain[c.Next]
	c.Next--
	return seed, true
}

type Node struct {
	NodeID   string
	Endpoint string // this node's own peer-server address, as reachable by others

	root   []byte
	dbPath string
	store  *store.Store
	orch   *protocol.OrchestratorClient
	peer   *peer.Client

	mu     sync.Mutex
	chains map[string]*ColdChain // chain_id -> state

	Watchdog *Watchdog
}

// SetLocalDBPath records where this node's own SQLite file lives, so
// ReadOwnDatabaseFile can back it up. Purely informational — the store
// itself doesn't need to know its own path.
func (n *Node) SetLocalDBPath(path string) { n.dbPath = path }

// ReadOwnDatabaseFile reads this node's local database file as raw bytes,
// for use with Backup() to protect the whole local database against
// device loss. This is a plain file read taken while the database may be
// open for writes — good enough for a demo snapshot; a production
// version would checkpoint (or briefly lock) the database first for a
// crash-consistent copy.
func (n *Node) ReadOwnDatabaseFile() ([]byte, error) {
	if n.dbPath == "" {
		return nil, fmt.Errorf("client: percorso del database locale non impostato")
	}
	return os.ReadFile(n.dbPath)
}

// AddMeshPeer registers a trusted-mesh member (a family/friend device, or
// another of the user's own devices) reachable at endpoint — expected to
// be an address on an already-established WireGuard tunnel, see package
// mesh. wgPublicKey is stored for reference/config-rendering; the actual
// trust boundary is enforced by the tunnel, not by this program.
func (n *Node) AddMeshPeer(name, endpoint, wgPublicKey string) error {
	return n.store.PutMeshPeer(store.MeshPeer{Name: name, Endpoint: endpoint, WGPublicKey: wgPublicKey})
}

func (n *Node) ListMeshPeers() ([]store.MeshPeer, error) {
	return n.store.ListMeshPeers()
}

func NewNode(nodeID, endpoint, orchestratorURL string, st *store.Store, root []byte) *Node {
	n := &Node{
		NodeID:   nodeID,
		Endpoint: endpoint,
		root:     root,
		store:    st,
		orch:     protocol.NewOrchestratorClient(orchestratorURL),
		peer:     peer.NewClient(),
		chains:   make(map[string]*ColdChain),
	}
	n.Watchdog = NewWatchdog(n)
	return n
}

// Start registers with the orchestrator and begins listening for pushed
// events (mutation seeds, map deltas) until ctx is cancelled.
func (n *Node) Start(ctx context.Context) error {
	if err := n.orch.Register(protocol.RegisterRequest{NodeID: n.NodeID, Endpoint: n.Endpoint}); err != nil {
		return fmt.Errorf("client: registrazione fallita: %w", err)
	}
	events, err := n.orch.SubscribeEvents(ctx, n.NodeID)
	if err != nil {
		return fmt.Errorf("client: sottoscrizione eventi fallita: %w", err)
	}
	go func() {
		for ev := range events {
			n.handleEvent(ev)
		}
	}()
	return nil
}

func (n *Node) handleEvent(ev protocol.Event) {
	switch ev.Type {
	case "mutation_seed":
		var seed protocol.MutationSeed
		if err := unmarshal(ev.Data, &seed); err != nil {
			log.Printf("[%s] evento mutation_seed malformato: %v", n.NodeID, err)
			return
		}
		if err := n.applyMutation(seed.PID, seed.Seed, "scheduled"); err != nil {
			// not every seed is for us — ignore pids we don't hold
			log.Printf("[%s] mutazione pianificata ignorata per pid=%s: %v", n.NodeID, seed.PID, err)
		}
	case "map_delta":
		// Deliberately not acted on here beyond logging: the orchestrator's
		// map cannot reveal which pids belong together, so it cannot drive
		// sibling-state reconciliation — only direct P2P gossip (see
		// peerserver.go's mutation-notice handler) can. The map stays
		// useful for peer discovery and reconstruction routing lookups.
	}
}

// registerNewFragment provisions a fragment's cold-mutation hash chain
// locally and announces it to the orchestrator on a best-effort basis.
// Announcing is NOT allowed to block acquiring the fragment: a
// family/friend node acting purely as an off-site backup host may have no
// orchestrator configured (or reachable) at all, and must still be able
// to accept custody of a share. The chain itself — which is what actually
// protects the fragment locally — is built and kept regardless.
func (n *Node) registerNewFragment(pid, chainID string) (*ColdChain, error) {
	chainValues, err := mcrypto.BuildChain(coldChainLength)
	if err != nil {
		return nil, err
	}
	cc := &ColdChain{Chain: chainValues, Next: coldChainLength - 1}
	// chain[coldChainLength] (the tip) is announced as the trusted anchor
	// and never revealed itself: the first cold mutation reveals
	// chain[coldChainLength-1], which the orchestrator can verify against it.
	n.mu.Lock()
	n.chains[chainID] = cc
	n.mu.Unlock()

	if err := n.orch.AnnounceRoute(protocol.RouteAnnounce{
		NodeID: n.NodeID, PID: pid, Endpoint: n.Endpoint,
		ChainID: chainID, ChainTip: chainValues[coldChainLength],
	}); err != nil {
		log.Printf("[%s] annuncio della rotta all'orchestratore fallito (nodo solo-mesh o isolato?): %v — il frammento resta comunque protetto localmente", n.NodeID, err)
	}
	return cc, nil
}

// applyMutation is the shared core of both scheduled and cold mutation:
// re-derive the key, re-encrypt the share content in place, rotate the
// pseudo-ID, persist, ack, and gossip to siblings.
func (n *Node) applyMutation(pid string, serverOrChainSeed []byte, reason string) error {
	frag, err := n.store.GetFragment(pid)
	if err != nil {
		return err
	}

	localEntropy := make([]byte, 32)
	if _, err := rand.Read(localEntropy); err != nil {
		return err
	}
	newKey, err := mcrypto.Advance(frag.Key, serverOrChainSeed, localEntropy)
	if err != nil {
		return err
	}
	mcrypto.Wipe(localEntropy)

	plaintext, err := mcrypto.Decrypt(frag.Key, frag.Ciphertext, []byte(frag.GroupID+":"+pid))
	if err != nil {
		return fmt.Errorf("client: decifratura con chiave corrente fallita: %w", err)
	}
	newPID := mcrypto.NextPseudoID(pid, serverOrChainSeed)
	newCiphertext, err := mcrypto.Encrypt(newKey, plaintext, []byte(frag.GroupID+":"+newPID))
	mcrypto.Wipe(plaintext)
	mcrypto.Wipe(frag.Key)
	if err != nil {
		return err
	}

	newEpoch := frag.Epoch + 1

	if err := n.store.PutFragment(store.Fragment{
		PID: newPID, GroupID: frag.GroupID, GroupToken: frag.GroupToken, ChainID: frag.ChainID,
		Epoch: newEpoch, Threshold: frag.Threshold, Total: frag.Total,
		Key: newKey, Ciphertext: newCiphertext, Members: frag.Members,
	}); err != nil {
		return err
	}
	if err := n.store.DeleteFragment(pid); err != nil {
		return err
	}

	commitment := commitmentHash(newPID, newCiphertext)
	ack := protocol.MutationAck{
		NodeID: n.NodeID, OldPID: pid, NewPID: newPID, Epoch: newEpoch,
		Commitment: commitment, Reason: reason, ChainID: frag.ChainID,
	}
	if reason == "cold" {
		ack.SeedUsed = serverOrChainSeed
	}
	if err := n.orch.Ack(ack); err != nil {
		log.Printf("[%s] impossibile notificare l'orchestratore (probabile isolamento): %v — la mutazione locale resta comunque valida", n.NodeID, err)
	}

	log.Printf("[%s] MUTAZIONE (%s): %s -> %s (epoch %d)", n.NodeID, reason, pid, newPID, newEpoch)
	n.notifySiblings(frag, pid, newPID)
	return nil
}

func (n *Node) notifySiblings(frag store.Fragment, oldPID, newPID string) {
	for _, m := range frag.Members {
		if m.NodeID == n.NodeID {
			continue
		}
		req := peer.MutationNoticeRequest{
			GroupID: frag.GroupID, GroupToken: frag.GroupToken,
			OldPID: oldPID, NewPID: newPID, NewEndpoint: n.Endpoint, Epoch: frag.Epoch + 1,
		}
		if err := n.peer.NotifyMutation(m.Endpoint, req); err != nil {
			log.Printf("[%s] notifica ai pari verso %s fallita (offline/isolato?): %v", n.NodeID, m.NodeID, err)
		}
	}
}

// ListLocalFragments returns every fragment currently held by this node,
// for status/inspection purposes.
func (n *Node) ListLocalFragments() ([]store.Fragment, error) {
	pids, err := n.store.ListFragmentPIDs()
	if err != nil {
		return nil, err
	}
	out := make([]store.Fragment, 0, len(pids))
	for _, pid := range pids {
		f, err := n.store.GetFragment(pid)
		if err != nil {
			continue
		}
		out = append(out, f)
	}
	return out, nil
}

// ColdMutate performs an offline mutation for pid using the next link of
// its pre-provisioned hash chain — no network round trip required. This
// is what the watchdog calls when it wants to react immediately.
func (n *Node) ColdMutate(pid string) error {
	frag, err := n.store.GetFragment(pid)
	if err != nil {
		return err
	}
	n.mu.Lock()
	cc, ok := n.chains[frag.ChainID]
	n.mu.Unlock()
	if !ok {
		return fmt.Errorf("client: nessuna hash-chain provisionata per %s", frag.ChainID)
	}
	seed, ok := cc.Consume()
	if !ok {
		return fmt.Errorf("client: hash-chain %s esaurita, serve un nuovo provisioning", frag.ChainID)
	}
	return n.applyMutation(pid, seed, "cold")
}
