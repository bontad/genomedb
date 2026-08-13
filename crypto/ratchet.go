package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"

	"golang.org/x/crypto/hkdf"
)

// KeySize is the size in bytes of every derived key in the system.
const KeySize = 32

// DeriveFragmentRoot derives the initial per-fragment key from the
// hardware-sealed root secret and a fragment-specific salt. This never
// leaves the client.
func DeriveFragmentRoot(rootSecret, fragmentSalt []byte) ([]byte, error) {
	return hkdfExpand(rootSecret, fragmentSalt, []byte("mutant-db/fragment-root"))
}

// Advance performs one step of the mutation ratchet: the next fragment
// key requires BOTH a fresh server-issued seed and freshly generated
// local entropy. The orchestrator supplies freshness (a client alone
// cannot precompute or be forced under duress to reveal a future key
// deterministically); the client supplies secrecy (the orchestrator alone
// never learns enough to derive K_n+1). Neither party in isolation can
// compute the resulting key.
func Advance(currentKey, serverSeed, localEntropy []byte) ([]byte, error) {
	if len(currentKey) == 0 || len(serverSeed) == 0 || len(localEntropy) == 0 {
		return nil, errors.New("crypto: ratchet inputs must be non-empty")
	}
	ikm := make([]byte, 0, len(serverSeed)+len(localEntropy))
	ikm = append(ikm, serverSeed...)
	ikm = append(ikm, localEntropy...)
	return hkdfExpand(ikm, currentKey, []byte("mutant-db/ratchet-step"))
}

func hkdfExpand(ikm, salt, info []byte) ([]byte, error) {
	r := hkdf.New(sha256.New, ikm, salt, info)
	out := make([]byte, KeySize)
	if _, err := io.ReadFull(r, out); err != nil {
		return nil, err
	}
	return out, nil
}

// NextPseudoID rotates a fragment's routing pseudonym: PID_n+1 =
// HMAC(PID_n, seed_n). The orchestrator can compute and verify this
// (it knows both PID_n and the seed it issued) without ever learning the
// fragment's real identity, which only cooperating P2P peers exchange.
func NextPseudoID(prevPseudoID string, serverSeed []byte) string {
	mac := hmac.New(sha256.New, serverSeed)
	mac.Write([]byte(prevPseudoID))
	return hex.EncodeToString(mac.Sum(nil))[:32]
}
