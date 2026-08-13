package client

import (
	"crypto/rand"
	"fmt"

	mcrypto "mutant-db/crypto"
	"mutant-db/peer"
	"mutant-db/store"
)

// Backup fragments data across this node's trusted mesh (family/friends'
// devices, reachable only because they're WireGuard peers — see package
// mesh) using the same erasure-coding primitives as Split, but with two
// deliberate differences that make it a genuine off-site backup rather
// than a mutation-protocol secret:
//
//  1. Peers come from the local trusted-mesh directory (store.MeshPeer),
//     never from the orchestrator's public node list — off-site backup
//     is designed to keep working even for a deployment with no
//     orchestrator at all.
//  2. This node does NOT keep a local share: the whole point is
//     surviving loss of this device, so a share held on it would be
//     worthless collateral, not protection.
func (n *Node) Backup(label string, data []byte, threshold int) error {
	meshPeers, err := n.store.ListMeshPeers()
	if err != nil {
		return err
	}
	return n.distributeBackup(label, data, threshold, meshPeers)
}

func (n *Node) distributeBackup(label string, data []byte, threshold int, meshPeers []store.MeshPeer) error {
	total := len(meshPeers)
	if total < threshold {
		return fmt.Errorf("client: servono almeno %d pari fidati raggiungibili, disponibili %d", threshold, total)
	}

	shares, err := mcrypto.Split(data, total, threshold)
	if err != nil {
		return fmt.Errorf("client: erasure coding fallito: %w", err)
	}

	groupID, err := randomID(16)
	if err != nil {
		return err
	}
	groupToken, err := randomID(32)
	if err != nil {
		return err
	}

	type holder struct {
		peer store.MeshPeer
		pid  string
	}
	holders := make([]holder, total)
	for i, p := range meshPeers {
		pid, err := randomID(16)
		if err != nil {
			return err
		}
		holders[i] = holder{p, pid}
	}

	members := make([]store.Member, total)
	peerMembers := make([]peer.Member, total)
	for i, h := range holders {
		m := store.Member{PID: h.pid, NodeID: h.peer.Name, Endpoint: h.peer.Endpoint}
		members[i] = m
		peerMembers[i] = peer.Member{PID: m.PID, NodeID: m.NodeID, Endpoint: m.Endpoint}
	}

	for i, h := range holders {
		key := make([]byte, mcrypto.KeySize)
		if _, err := rand.Read(key); err != nil {
			return err
		}
		aad := []byte(groupID + ":" + h.pid)
		ciphertext, err := mcrypto.Encrypt(key, shares[i], aad)
		if err != nil {
			return err
		}
		err = n.peer.DeliverShare(h.peer.Endpoint, peer.DeliverShareRequest{
			GroupID: groupID, GroupToken: groupToken, PID: h.pid, Epoch: 0,
			Threshold: threshold, Total: total, Key: key, Ciphertext: ciphertext,
			Members: peerMembers,
		})
		mcrypto.Wipe(key) // handed off over the wire (the one legitimate crossing, see peer/messages.go) — no reason to keep our copy
		mcrypto.Wipe(shares[i])
		if err != nil {
			return fmt.Errorf("client: consegna della quota di backup a %s fallita: %w", h.peer.Name, err)
		}
	}

	return n.store.PutManifest(store.Manifest{
		SecretName: label, Kind: "backup", GroupID: groupID, GroupToken: groupToken,
		Threshold: threshold, Total: total, Members: members,
	})
}
