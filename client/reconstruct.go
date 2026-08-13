package client

import (
	"fmt"
	"log"

	mcrypto "mutant-db/crypto"
)

// Reconstruct fetches at least `threshold` shares of a previously split
// secret and recombines them. Shares are addressed by stable group_id, so
// this works even if members have mutated (or been offline and mutated
// without this node's manifest ever hearing about it directly) since the
// manifest was last updated — that's the point of resolving by group
// membership + token rather than by a remembered pseudo-ID.
func (n *Node) Reconstruct(secretName string) ([]byte, error) {
	m, err := n.store.GetManifest(secretName)
	if err != nil {
		return nil, fmt.Errorf("client: nessun manifest locale per %q: %w", secretName, err)
	}

	shares := make([]mcrypto.Share, 0, m.Threshold)
	for _, member := range m.Members {
		if len(shares) >= m.Threshold {
			break
		}
		if member.NodeID == n.NodeID {
			frag, err := n.store.GetFragmentByGroup(m.GroupID)
			if err != nil {
				log.Printf("client: quota locale mancante per il gruppo %s: %v", m.GroupID, err)
				continue
			}
			plain, err := mcrypto.Decrypt(frag.Key, frag.Ciphertext, []byte(frag.GroupID+":"+frag.PID))
			if err != nil {
				log.Printf("client: decifratura locale fallita: %v", err)
				continue
			}
			shares = append(shares, mcrypto.Share(plain))
			continue
		}
		resp, err := n.peer.FetchGroupShare(member.Endpoint, m.GroupID, m.GroupToken)
		if err != nil {
			log.Printf("client: quota di %s irraggiungibile (isolato/offline?), provo il prossimo: %v", member.NodeID, err)
			continue
		}
		shares = append(shares, mcrypto.Share(resp.Share))
	}

	if len(shares) < m.Threshold {
		return nil, fmt.Errorf("client: solo %d/%d quote disponibili (soglia %d) — impossibile ricostruire", len(shares), m.Total, m.Threshold)
	}
	secret, err := mcrypto.Combine(shares)
	for _, s := range shares {
		mcrypto.Wipe(s) // each share alone reveals nothing (Shamir), but no reason to let them linger either
	}
	return secret, err
}
