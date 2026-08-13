// Package crypto implements the cryptographic core of the mutation
// protocol: GF(256) Shamir secret sharing, an HKDF-based key ratchet that
// requires both server and local entropy to advance, AES-256-GCM sealing,
// a hardware-seal stand-in, and the S/KEY-style hash chain used for
// offline "cold" mutation.
package crypto

// GF(2^8) arithmetic, same field AES uses (reduction polynomial x^8+x^4+x^3+x+1,
// i.e. 0x11B), needed for Shamir secret sharing over bytes.

var expTable [255]byte
var logTable [256]byte

func init() {
	x := byte(1)
	for i := 0; i < 255; i++ {
		expTable[i] = x
		logTable[x] = byte(i)
		x = gfMulSlow(x, 3) // 0x03 is a generator of GF(256) under this polynomial
	}
}

func gfMulSlow(a, b byte) byte {
	var p byte
	for i := 0; i < 8; i++ {
		if b&1 != 0 {
			p ^= a
		}
		hiBitSet := a & 0x80
		a <<= 1
		if hiBitSet != 0 {
			a ^= 0x1B
		}
		b >>= 1
	}
	return p
}

func gfMul(a, b byte) byte {
	if a == 0 || b == 0 {
		return 0
	}
	sum := int(logTable[a]) + int(logTable[b])
	if sum >= 255 {
		sum -= 255
	}
	return expTable[sum]
}

func gfDiv(a, b byte) byte {
	if a == 0 {
		return 0
	}
	if b == 0 {
		panic("crypto: division by zero in GF(256)")
	}
	diff := int(logTable[a]) - int(logTable[b])
	if diff < 0 {
		diff += 255
	}
	return expTable[diff]
}
