// Package mesh provides the pieces needed to treat a user's own devices
// plus a circle of trusted family/friends as off-site backup
// infrastructure: WireGuard key generation/config rendering, so the
// actual tunnel is a standard `wg-quick` setup the user controls, not
// something this program manages at the OS/kernel level.
//
// Everything above the tunnel (client/backup.go) only ever talks to peer
// endpoints — it has no idea whether those addresses are reachable
// because of WireGuard, a LAN, or anything else. That's deliberate: the
// "trusted mesh" property comes entirely from the fact that only
// WireGuard peers can route to those addresses at all, which is a
// property of the tunnel, not of this program.
package mesh

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"golang.org/x/crypto/curve25519"
)

// KeyPair is a WireGuard-compatible Curve25519 keypair, base64-encoded
// exactly like `wg genkey`/`wg pubkey` produce.
type KeyPair struct {
	PrivateKey string
	PublicKey  string
}

// GenerateKeyPair creates a fresh WireGuard keypair. The private key
// never needs to touch this program again after the user installs it
// into their wg-quick config — mutant-db only ever needs to know peers'
// public keys and tunnel addresses.
func GenerateKeyPair() (KeyPair, error) {
	var priv [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		return KeyPair{}, err
	}
	clamp(&priv)
	pub, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return KeyPair{}, err
	}
	return KeyPair{
		PrivateKey: base64.StdEncoding.EncodeToString(priv[:]),
		PublicKey:  base64.StdEncoding.EncodeToString(pub),
	}, nil
}

// clamp applies the standard X25519/WireGuard private-key clamping
// (RFC 7748 §5): clear the low 3 bits and the high bit, set the
// second-highest bit.
func clamp(k *[32]byte) {
	k[0] &= 248
	k[31] &= 127
	k[31] |= 64
}

// RenderInterfaceConfig produces the [Interface] stanza for this device's
// own wg-quick config.
func RenderInterfaceConfig(privateKey, tunnelCIDR string, listenPort int) string {
	return fmt.Sprintf("[Interface]\nPrivateKey = %s\nAddress = %s\nListenPort = %d\n", privateKey, tunnelCIDR, listenPort)
}

// RenderPeerConfig produces one [Peer] stanza to append for each trusted
// mesh member. endpoint is optional (leave empty for a peer that roams /
// has no stable public address — WireGuard will still accept its
// handshakes once it initiates).
func RenderPeerConfig(name, publicKey, allowedIPs, endpoint string) string {
	s := fmt.Sprintf("# %s\n[Peer]\nPublicKey = %s\nAllowedIPs = %s\n", name, publicKey, allowedIPs)
	if endpoint != "" {
		s += fmt.Sprintf("Endpoint = %s\n", endpoint)
	}
	return s
}
