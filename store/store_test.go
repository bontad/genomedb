package store

import (
	"bytes"
	"path/filepath"
	"testing"
)

func TestFragmentRoundTrip(t *testing.T) {
	dir := t.TempDir()
	root := bytes.Repeat([]byte{0x42}, 32)
	s, err := Open(filepath.Join(dir, "node.db"), root)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	f := Fragment{
		PID:        "pid-aaa",
		GroupID:    "group-1",
		GroupToken: "tok-1",
		Epoch:      3,
		Threshold:  2,
		Total:      3,
		Key:        bytes.Repeat([]byte{0x07}, 32),
		Ciphertext: []byte("not really plaintext, this is AEAD ciphertext"),
		Members: []Member{
			{PID: "pid-aaa", NodeID: "n1", Endpoint: "http://localhost:9001"},
			{PID: "pid-bbb", NodeID: "n2", Endpoint: "http://localhost:9002"},
		},
	}
	if err := s.PutFragment(f); err != nil {
		t.Fatal(err)
	}

	got, err := s.GetFragment("pid-aaa")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Key, f.Key) {
		t.Fatal("key did not round-trip through wrap/unwrap")
	}
	if !bytes.Equal(got.Ciphertext, f.Ciphertext) {
		t.Fatal("ciphertext mismatch")
	}
	if len(got.Members) != 2 || got.Members[1].PID != "pid-bbb" {
		t.Fatalf("members mismatch: %+v", got.Members)
	}

	// wrong root -> must not be able to unwrap the key
	wrongRoot := bytes.Repeat([]byte{0x99}, 32)
	s2, err := Open(filepath.Join(dir, "node.db"), wrongRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if _, err := s2.GetFragment("pid-aaa"); err == nil {
		t.Fatal("expected unwrap failure with a different node root")
	}

	if err := s.UpdateSibling("group-1", "pid-bbb", "pid-ccc", "http://localhost:9003"); err != nil {
		t.Fatal(err)
	}
	got2, err := s.GetFragment("pid-aaa")
	if err != nil {
		t.Fatal(err)
	}
	if got2.Members[1].PID != "pid-ccc" {
		t.Fatalf("sibling rotation not reflected: %+v", got2.Members)
	}
}
