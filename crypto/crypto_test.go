package crypto

import (
	"bytes"
	"testing"
)

func TestShamirRoundTrip(t *testing.T) {
	secret := []byte("this is a 32-byte fragment key!")
	shares, err := Split(secret, 5, 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(shares) != 5 {
		t.Fatalf("expected 5 shares, got %d", len(shares))
	}
	// any 3 of 5 reconstruct
	got, err := Combine([]Share{shares[1], shares[3], shares[4]})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatalf("mismatch: got %q want %q", got, secret)
	}
	// a different subset of 3 must also work
	got2, err := Combine([]Share{shares[0], shares[2], shares[4]})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got2, secret) {
		t.Fatalf("mismatch on second subset: got %q want %q", got2, secret)
	}
}

func TestShamirBelowThresholdIsWrong(t *testing.T) {
	secret := []byte("top secret fragment payload!!!!")
	shares, err := Split(secret, 5, 3)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Combine([]Share{shares[0], shares[1]}) // only 2 of 3 needed
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(got, secret) {
		t.Fatal("reconstructed secret with too few shares — threshold property broken")
	}
}

func TestRatchetRequiresBothInputs(t *testing.T) {
	k0 := []byte("0123456789abcdef0123456789abcdef"[:32])
	seed := []byte("server-seed-32-bytes-aaaaaaaaaaa"[:32])
	local := []byte("local-entropy-32-bytes-bbbbbbbbb"[:32])

	k1, err := Advance(k0, seed, local)
	if err != nil {
		t.Fatal(err)
	}
	// Same server seed, different local entropy -> different key: the
	// orchestrator alone cannot predict the outcome.
	local2 := []byte("local-entropy-32-bytes-cccccccccc"[:32])
	k1b, err := Advance(k0, seed, local2)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(k1, k1b) {
		t.Fatal("ratchet output identical despite different local entropy")
	}

	// Same local entropy, different server seed -> different key: the
	// client alone cannot predict the outcome either.
	seed2 := []byte("server-seed-32-bytes-dddddddddddd"[:32])
	k1c, err := Advance(k0, seed2, local)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(k1, k1c) {
		t.Fatal("ratchet output identical despite different server seed")
	}
}

func TestSealRoundTrip(t *testing.T) {
	dir := t.TempDir()
	binding := []byte("stand-in-hardware-fingerprint")

	root1, err := LoadOrCreateRoot(dir, binding)
	if err != nil {
		t.Fatal(err)
	}
	root2, err := LoadOrCreateRoot(dir, binding)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(root1, root2) {
		t.Fatal("unsealing the same file twice produced different roots")
	}

	wrongBinding := []byte("wrong-hardware-fingerprint")
	if _, err := LoadOrCreateRoot(dir, wrongBinding); err == nil {
		t.Fatal("unsealing with the wrong binding should fail")
	}
}

func TestHashChain(t *testing.T) {
	chain, err := BuildChain(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(chain) != 11 {
		t.Fatalf("expected 11 entries, got %d", len(chain))
	}
	for i := 0; i < 10; i++ {
		if !VerifyStep(chain[i], chain[i+1]) {
			t.Fatalf("chain step %d does not verify forward", i)
		}
	}
	// a random value must not verify
	fake := make([]byte, 32)
	if VerifyStep(fake, chain[5]) {
		t.Fatal("VerifyStep accepted an unrelated value")
	}
}
