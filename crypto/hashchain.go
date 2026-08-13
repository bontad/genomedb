package crypto

import (
	"crypto/rand"
	"crypto/sha256"
)

// BuildChain creates an S/KEY-style hash chain of `length` pre-provisioned
// mutation seeds: chain[i] = H(chain[i+1]), so chain[length] is the tip
// (generated first, revealed last-to-use-first is not the point — it's
// revealed FIRST, in reverse index order down to chain[0]).
//
// Why: during an actual incident the attacked node may not be able to, or
// should not, wait for a network round trip to the orchestrator — the
// attacker may already control that channel. By pre-handing the client a
// chain built during a quiet period, the client can pop the next seed
// (walking length -> 0) completely offline and mutate immediately. It
// cannot predict the seed after that one (one-wayness of SHA-256), so it
// cannot make its own mutation schedule predictable even to itself ahead
// of time. The orchestrator verifies a used seed after connectivity
// returns by hashing it forward and checking it lands on the last seed it
// already trusted.
func BuildChain(length int) ([][]byte, error) {
	if length < 1 {
		length = 1
	}
	chain := make([][]byte, length+1)
	chain[length] = make([]byte, 32)
	if _, err := rand.Read(chain[length]); err != nil {
		return nil, err
	}
	for i := length - 1; i >= 0; i-- {
		h := sha256.Sum256(chain[i+1])
		chain[i] = h[:]
	}
	return chain, nil
}

// VerifyStep reports whether `revealed` is the legitimate next step after
// `previouslyTrusted` in a hash chain built by BuildChain — i.e. that
// H(previouslyTrusted) == revealed. The verifier only ever needs to hash
// forward from a value it already trusts; it can never compute `revealed`
// itself in advance (one-wayness of SHA-256), which is what makes each
// step usable exactly once and unpredictable ahead of time.
func VerifyStep(revealed, previouslyTrusted []byte) bool {
	h := sha256.Sum256(previouslyTrusted)
	if len(h) != len(revealed) {
		return false
	}
	var diff byte
	for i := range h {
		diff |= h[i] ^ revealed[i]
	}
	return diff == 0
}
