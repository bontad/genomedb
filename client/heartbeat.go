package client

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"time"

	"mutant-db/protocol"
)

// RunHeartbeats sends a periodic proof-of-possession heartbeat for every
// fragment this node currently holds, until ctx is cancelled.
func (n *Node) RunHeartbeats(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			n.sendHeartbeats()
		case <-ctx.Done():
			return
		}
	}
}

func (n *Node) sendHeartbeats() {
	pids, err := n.store.ListFragmentPIDs()
	if err != nil {
		return
	}
	for _, pid := range pids {
		frag, err := n.store.GetFragment(pid)
		if err != nil {
			continue
		}
		h := sha256.Sum256(frag.Ciphertext)
		risk := 0
		if n.Watchdog != nil {
			risk = n.Watchdog.Score()
		}
		n.orch.Heartbeat(protocol.Heartbeat{
			NodeID: n.NodeID, PID: pid, Epoch: frag.Epoch,
			RiskScore: risk, PorProof: hex.EncodeToString(h[:8]),
		})
	}
}
