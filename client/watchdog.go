package client

import (
	"context"
	"log"
	"os"
	"sync"
	"time"

	"mutant-db/protocol"
)

// signals holds one tick's worth of raw watchdog observations. Individual
// checks are platform-specific (watchdog_darwin.go, watchdog_linux.go,
// watchdog_windows.go); this file only fuses them into a score and drives
// the reaction, which is where false-positive containment lives.
type signals struct {
	remoteSession    bool // interactive remote admin session detected (SSH env / RDP session type)
	debuggerAttached bool // OS-level trace/debug flag set on this process
	reparented       bool // parent process changed unexpectedly since startup — a common post-injection artifact
}

// Weights are calibrated so that NO single signal alone crosses
// scoreSuspect — reparenting in particular is routine for daemons started
// via nohup/systemd/docker and must never trigger on its own, only in
// correlation with something else (see §5.3 of the design: correlation
// required, not single-trigger).
const (
	weightRemoteSession    = 15
	weightDebuggerAttached = 60
	weightReparented       = 10

	scoreSuspect  = 20 // -> silent local micro-mutation, no alert
	scoreConfirm  = 55 // -> full mutation + IMMUNE_ALERT, but only after debounce
	confirmStreak = 2  // consecutive ticks >= scoreConfirm required before acting
)

// Watchdog fuses weak, individually-noisy signals into a score with
// hysteresis, exactly so that no single signal (an admin's legitimate RDP
// session, one slow tick, a debugger the developer forgot was attached)
// can alone trigger a full mutation. See the design doc's §5.2/§5.3 for
// the reasoning this mirrors.
type Watchdog struct {
	node *Node

	mu             sync.Mutex
	lastScore      int
	confirmedTicks int
	startPPID      int
	cooldownUntil  time.Time
}

func NewWatchdog(n *Node) *Watchdog {
	return &Watchdog{node: n, startPPID: os.Getppid()}
}

func (w *Watchdog) Score() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.lastScore
}

// Run polls the local signals on a fixed cadence until ctx is cancelled.
// The cadence is intentionally short (this is local heuristic polling,
// not network traffic) — it does not affect the "no reshuffle storms"
// bandwidth goal, which is about the network mutation protocol, not local
// sensing.
func (w *Watchdog) Run(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			w.tick()
		case <-ctx.Done():
			return
		}
	}
}

func (w *Watchdog) tick() {
	s := signals{
		remoteSession:    detectRemoteSession(),
		debuggerAttached: detectDebugger(),
		reparented:       os.Getppid() != w.startPPID,
	}
	score := 0
	if s.remoteSession {
		score += weightRemoteSession
	}
	if s.debuggerAttached {
		score += weightDebuggerAttached
	}
	if s.reparented {
		score += weightReparented
	}

	w.mu.Lock()
	w.lastScore = score
	inCooldown := time.Now().Before(w.cooldownUntil)
	if score >= scoreConfirm {
		w.confirmedTicks++
	} else {
		w.confirmedTicks = 0
	}
	confirmed := w.confirmedTicks >= confirmStreak
	suspect := score >= scoreSuspect
	w.mu.Unlock()

	if inCooldown {
		return
	}
	switch {
	case confirmed:
		w.react("confirmed", true)
	case suspect:
		w.react("suspect", false)
	}
}

// SimulateAttack lets an operator (or this demo's CLI) force the
// confirmed-incident reaction immediately, without waiting for real
// signals to correlate — useful for exercising the response path.
func (w *Watchdog) SimulateAttack() {
	log.Printf("[%s] *** attacco simulato: innesco reazione immunitaria completa ***", w.node.NodeID)
	w.react("confirmed", true)
}

func (w *Watchdog) react(severity string, alert bool) {
	w.mu.Lock()
	cooldown := 10 * time.Second
	if severity == "confirmed" {
		cooldown = 20 * time.Second
	}
	w.cooldownUntil = time.Now().Add(cooldown)
	w.confirmedTicks = 0
	w.mu.Unlock()

	// Fast, local, immediate: rotate key+identity of whatever this node
	// physically holds. Runs even for a node with no local fragments
	// (e.g. a pure backup owner) — the loop below just does nothing then.
	if pids, err := w.node.store.ListFragmentPIDs(); err == nil && len(pids) > 0 {
		log.Printf("[%s] risposta immunitaria (%s): mutazione a freddo di %d frammenti locali", w.node.NodeID, severity, len(pids))
		for _, pid := range pids {
			if err := w.node.ColdMutate(pid); err != nil {
				log.Printf("[%s] mutazione a freddo fallita per pid=%s: %v", w.node.NodeID, pid, err)
				continue
			}
			if alert {
				_ = w.node.orch.Alert(protocol.ImmuneAlert{
					NodeID: w.node.NodeID, PID: pid, Severity: severity, At: time.Now(),
				})
			}
		}
	}

	// Slower, network-dependent, more thorough: a CONFIRMED incident means
	// this node's own knowledge of every group it owns — not just what it
	// physically holds — may be tainted. ColdMutate above only protects
	// this node's copy; a forced reshare invalidates every OTHER holder's
	// copy too, via a fresh Shamir polynomial (see ForceReshareOwned).
	// Backgrounded so a slow reconstruct/redistribute round trip doesn't
	// stall the watchdog's own polling loop.
	if severity == "confirmed" {
		go w.node.ForceReshareOwned()
	}
}
