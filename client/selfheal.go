package client

import (
	"context"
	"log"
	"time"

	mcrypto "mutant-db/crypto"
	"mutant-db/store"
)

// SelfHeal periodically checks every manifest this node owns — both
// "backup" (mesh-hosted) and "secret" (orchestrator-routed) — and, if the
// number of currently reachable holders has dropped to within `margin`
// shares of the recovery threshold, reconstructs from whichever peers are
// still alive and redistributes a FRESH Shamir split (a new random
// polynomial, not the same shares re-sent).
//
// That last part matters beyond availability: because crypto.Split draws
// fresh randomness every call, none of the new share values match the
// old ones — this is what the design doc calls "proactive secret
// sharing." A share an attacker exfiltrated from a since-departed holder
// becomes permanently useless the moment a heal cycle runs, not just
// unavailable. This applies uniformly to both kinds now: node loss and
// quiet key/polynomial rotation are the same code path for backups AND
// for regular mutation-protocol secrets, closing what was originally a
// gap only backups were protected against.
func (n *Node) SelfHeal(ctx context.Context, interval time.Duration, margin int) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			n.healManifests(margin)
		case <-ctx.Done():
			return
		}
	}
}

// HealNow runs one self-heal cycle immediately instead of waiting for the
// next scheduled tick — used by the CLI's `heal-now`, and by the watchdog
// on a confirmed incident (with margin effectively ignored — see
// ForceReshareOwned in watchdog.go).
func (n *Node) HealNow() {
	n.healManifests(1)
}

// ForceReshareOwned reshares EVERY manifest this node owns — both kinds —
// unconditionally, ignoring alive-count/margin entirely. Unlike
// healManifests (triggered by node loss: "are enough peers still up"),
// this is triggered by a CONFIRMED local incident: the concern isn't
// availability, it's that this node's own knowledge of the group (which
// pids, which keys, which peers) may have been exposed. A fresh
// polynomial invalidates every share in the group, including the ones
// held by OTHER nodes that were never themselves touched — ColdMutate
// alone only protects the copy held locally. See watchdog.go's react().
func (n *Node) ForceReshareOwned() {
	var manifests []store.Manifest
	for _, kind := range [2]string{"backup", "secret"} {
		ms, err := n.store.ListManifestsByKind(kind)
		if err != nil {
			log.Printf("[%s] re-share forzato: impossibile elencare i manifest (%s): %v", n.NodeID, kind, err)
			continue
		}
		manifests = append(manifests, ms...)
	}
	if len(manifests) == 0 {
		return
	}
	log.Printf("[%s] incidente confermato: re-share forzato di %d manifest posseduti", n.NodeID, len(manifests))
	for _, m := range manifests {
		n.reshareManifest(m)
	}
}

func (n *Node) healManifests(margin int) {
	var manifests []store.Manifest
	for _, kind := range [2]string{"backup", "secret"} {
		ms, err := n.store.ListManifestsByKind(kind)
		if err != nil {
			log.Printf("[%s] auto-guarigione: impossibile elencare i manifest (%s): %v", n.NodeID, kind, err)
			continue
		}
		manifests = append(manifests, ms...)
	}
	for _, m := range manifests {
		n.healOne(m, margin)
	}
}

func (n *Node) healOne(m store.Manifest, margin int) {
	alive := n.probeMembers(m)
	log.Printf("[%s] auto-guarigione: %q (%s) — %d/%d pari vivi (soglia %d)", n.NodeID, m.SecretName, m.Kind, len(alive), m.Total, m.Threshold)

	if len(alive) >= m.Total {
		return // every holder from the last (re)share is still alive — nothing changed, nothing to heal
	}
	if len(alive) < m.Threshold {
		log.Printf("[%s] *** CRITICO: %q sotto soglia di recupero (%d/%d), impossibile ricostruire ***", n.NodeID, m.SecretName, len(alive), m.Threshold)
		return
	}
	if len(alive) > m.Threshold+margin {
		return // lost some redundancy but still comfortably above threshold — not urgent yet
	}
	n.reshareManifest(m)
}

// probeMembers returns which of a manifest's members currently confirm
// (via the no-reveal presence check) that they still hold a live share.
func (n *Node) probeMembers(m store.Manifest) []store.Member {
	var alive []store.Member
	for _, mem := range m.Members {
		resp, err := n.peer.CheckPresence(mem.Endpoint, m.GroupID, m.GroupToken)
		if err != nil || !resp.Present {
			continue
		}
		alive = append(alive, mem)
	}
	return alive
}

// reshareManifest reconstructs a manifest's secret from whichever members
// currently answer (reusing Reconstruct's own per-member fault tolerance,
// rather than duplicating that logic here) and redistributes it fresh.
// Where it redistributes depends on the manifest's kind: mesh peers for a
// backup, the orchestrator's node directory for a regular secret — same
// as Backup() vs Split() normally source their peers.
func (n *Node) reshareManifest(m store.Manifest) {
	data, err := n.Reconstruct(m.SecretName)
	if err != nil {
		log.Printf("[%s] auto-guarigione: ricostruzione fallita per %q, riprovo al prossimo ciclo: %v", n.NodeID, m.SecretName, err)
		return
	}
	defer mcrypto.Wipe(data)

	switch m.Kind {
	case "backup":
		meshPeers, err := n.store.ListMeshPeers()
		if err != nil {
			log.Printf("[%s] auto-guarigione: impossibile leggere la mesh fidata: %v", n.NodeID, err)
			return
		}
		var reachable []store.MeshPeer
		for _, p := range meshPeers {
			if err := n.peer.Ping(p.Endpoint); err == nil {
				reachable = append(reachable, p)
			}
		}
		if len(reachable) < m.Threshold {
			log.Printf("[%s] auto-guarigione: solo %d pari mesh raggiungibili (< soglia %d), mantengo la distribuzione esistente", n.NodeID, len(reachable), m.Threshold)
			return
		}
		if err := n.distributeBackup(m.SecretName, data, m.Threshold, reachable); err != nil {
			log.Printf("[%s] auto-guarigione fallita per il backup %q: %v", n.NodeID, m.SecretName, err)
			return
		}
		log.Printf("[%s] *** AUTO-GUARIGIONE: backup %q ridistribuito su %d pari mesh con polinomio Shamir fresco — le quote precedenti sono ormai inutili ***", n.NodeID, m.SecretName, len(reachable))

	default: // "secret" — orchestrator-routed
		if err := n.Split(m.SecretName, data, m.Threshold, m.Total); err != nil {
			log.Printf("[%s] auto-guarigione fallita per il segreto %q: %v", n.NodeID, m.SecretName, err)
			return
		}
		log.Printf("[%s] *** AUTO-GUARIGIONE: segreto %q ri-frammentato su %d pari con polinomio Shamir fresco — le quote precedenti sono ormai inutili ***", n.NodeID, m.SecretName, m.Total)
	}
}
