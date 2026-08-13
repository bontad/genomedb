package crypto

import (
	"crypto/rand"
	"errors"
	"fmt"
)

// Share is one participant's fragment of a split secret: byte 0 is the
// x-coordinate (1..255), the rest are y-values, one per secret byte.
type Share []byte

// Split divides secret into `shares` fragments such that any `threshold`
// of them reconstruct it exactly, and any threshold-1 reveal nothing
// (information-theoretic, not just computational, security).
func Split(secret []byte, shares, threshold int) ([]Share, error) {
	if threshold < 2 {
		return nil, errors.New("crypto: threshold must be >= 2")
	}
	if shares < threshold {
		return nil, errors.New("crypto: shares must be >= threshold")
	}
	if shares > 255 {
		return nil, errors.New("crypto: shares must be <= 255")
	}
	if len(secret) == 0 {
		return nil, errors.New("crypto: secret must not be empty")
	}

	out := make([]Share, shares)
	for i := range out {
		out[i] = make(Share, len(secret)+1)
		out[i][0] = byte(i + 1)
	}

	coeffs := make([]byte, threshold)
	for byteIdx, secretByte := range secret {
		coeffs[0] = secretByte
		if _, err := rand.Read(coeffs[1:]); err != nil {
			return nil, fmt.Errorf("crypto: generating polynomial coefficients: %w", err)
		}
		for i := 0; i < shares; i++ {
			out[i][byteIdx+1] = evalPoly(coeffs, byte(i+1))
		}
	}
	return out, nil
}

func evalPoly(coeffs []byte, x byte) byte {
	result := coeffs[len(coeffs)-1]
	for i := len(coeffs) - 2; i >= 0; i-- {
		result = gfMul(result, x) ^ coeffs[i]
	}
	return result
}

// Combine reconstructs the secret from >= threshold shares via Lagrange
// interpolation at x=0. Fewer than threshold shares produce garbage, not
// an error — Shamir sharing gives no way to distinguish "too few shares"
// from "wrong shares" without an external integrity check (the caller
// should AEAD-verify the recovered key/plaintext).
func Combine(shares []Share) ([]byte, error) {
	if len(shares) < 2 {
		return nil, errors.New("crypto: need at least 2 shares")
	}
	secretLen := len(shares[0]) - 1
	if secretLen <= 0 {
		return nil, errors.New("crypto: malformed share")
	}
	xs := make([]byte, len(shares))
	seen := make(map[byte]bool, len(shares))
	for i, s := range shares {
		if len(s) != secretLen+1 {
			return nil, errors.New("crypto: mismatched share lengths")
		}
		if s[0] == 0 {
			return nil, errors.New("crypto: invalid share (x=0)")
		}
		if seen[s[0]] {
			return nil, errors.New("crypto: duplicate share x-coordinate")
		}
		seen[s[0]] = true
		xs[i] = s[0]
	}

	secret := make([]byte, secretLen)
	for byteIdx := 0; byteIdx < secretLen; byteIdx++ {
		var acc byte
		for i := range shares {
			yi := shares[i][byteIdx+1]
			var num, den byte = 1, 1
			for j := range shares {
				if i == j {
					continue
				}
				num = gfMul(num, xs[j])
				den = gfMul(den, xs[i]^xs[j])
			}
			acc ^= gfMul(yi, gfDiv(num, den))
		}
		secret[byteIdx] = acc
	}
	return secret, nil
}
