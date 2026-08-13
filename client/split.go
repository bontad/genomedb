package client

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"

	mcrypto "mutant-db/crypto"
	"mutant-db/peer"
	"mutant-db/protocol"
	"mutant-db/store"
)

func randomID(nBytes int) (string, error) {
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// reachablePeers asks the orchestrator for the registered node directory,
// then pings each candidate (excluding self) to find `need` that are
// actually up right now, instead of blindly picking the first `need`
// registered and aborting the whole split the moment one of them turns
// out to be down. Registration and liveness are different things — a
// node can stay registered long after it's gone quiet.
func (n *Node) reachablePeers(need int) ([]protocol.NodeInfo, error) {
	nodes, err := n.orch.ListNodes()
	if err != nil {
		return nil, fmt.Errorf("client: impossibile elencare i nodi: %w", err)
	}
	var reachable []protocol.NodeInfo
	for _, nd := range nodes {
		if nd.NodeID == n.NodeID {
			continue
		}
		if err := n.peer.Ping(nd.Endpoint); err != nil {
			continue
		}
		reachable = append(reachable, nd)
		if len(reachable) == need {
			break
		}
	}
	if len(reachable) < need {
		return nil, fmt.Errorf("client: servono %d pari raggiungibili, disponibili solo %d (su %d registrati)", need, len(reachable), len(nodes))
	}
	return reachable, nil
}

// Split fragments data into `total` Shamir shares (any `threshold`
// reconstruct it), keeps one locally, and hands the rest to peers
// discovered through the orchestrator's node directory. The orchestrator
// only ever sees, per fragment, an opaque pseudo-ID and which endpoint
// answers for it — never that these particular pseudo-IDs together
// reconstruct `secretName`, and never the plaintext or any derived key.
func (n *Node) Split(secretName string, data []byte, threshold, total int) error {
	if total < 2 {
		return fmt.Errorf("client: total deve essere >= 2")
	}
	peers, err := n.reachablePeers(total - 1)
	if err != nil {
		return err
	}

	shares, err := mcrypto.Split(data, total, threshold)
	if err != nil {
		return fmt.Errorf("client: shamir split fallito: %w", err)
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
		nodeID, endpoint, pid string
	}
	holders := make([]holder, total)
	pid0, err := randomID(16)
	if err != nil {
		return err
	}
	holders[0] = holder{n.NodeID, n.Endpoint, pid0}
	for i, p := range peers {
		pid, err := randomID(16)
		if err != nil {
			return err
		}
		holders[i+1] = holder{p.NodeID, p.Endpoint, pid}
	}

	members := make([]store.Member, total)
	for i, h := range holders {
		members[i] = store.Member{PID: h.pid, NodeID: h.nodeID, Endpoint: h.endpoint}
	}
	peerMembers := make([]peer.Member, total)
	for i, h := range holders {
		peerMembers[i] = peer.Member{PID: h.pid, NodeID: h.nodeID, Endpoint: h.endpoint}
	}

	for i, h := range holders {
		aad := []byte(groupID + ":" + h.pid)
		var key []byte
		if i == 0 {
			salt, err := randomID(16)
			if err != nil {
				return err
			}
			key, err = mcrypto.DeriveFragmentRoot(n.root, []byte(salt))
			if err != nil {
				return err
			}
		} else {
			key = make([]byte, mcrypto.KeySize)
			if _, err := rand.Read(key); err != nil {
				return err
			}
		}
		ciphertext, err := mcrypto.Encrypt(key, shares[i], aad)
		if err != nil {
			return err
		}

		if i == 0 {
			chainID, err := randomID(8)
			if err != nil {
				return err
			}
			if _, err := n.registerNewFragment(h.pid, chainID); err != nil {
				return err
			}
			err = n.store.PutFragment(store.Fragment{
				PID: h.pid, GroupID: groupID, GroupToken: groupToken, ChainID: chainID,
				Epoch: 0, Threshold: threshold, Total: total,
				Key: key, Ciphertext: ciphertext, Members: members,
			})
			mcrypto.Wipe(key)
			mcrypto.Wipe(shares[i])
			if err != nil {
				return err
			}
			continue
		}

		err = n.peer.DeliverShare(h.endpoint, peer.DeliverShareRequest{
			GroupID: groupID, GroupToken: groupToken, PID: h.pid, Epoch: 0,
			Threshold: threshold, Total: total, Key: key, Ciphertext: ciphertext,
			Members: peerMembers,
		})
		mcrypto.Wipe(key)
		mcrypto.Wipe(shares[i])
		if err != nil {
			return fmt.Errorf("client: consegna della quota a %s fallita: %w", h.nodeID, err)
		}
	}

	return n.store.PutManifest(store.Manifest{
		SecretName: secretName, Kind: "secret", GroupID: groupID, GroupToken: groupToken,
		Threshold: threshold, Total: total, Members: members,
	})
}

