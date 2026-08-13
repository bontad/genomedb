package client

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

func unmarshal(data json.RawMessage, v any) error {
	return json.Unmarshal(data, v)
}

func commitmentHash(pid string, ciphertext []byte) string {
	h := sha256.New()
	h.Write([]byte(pid))
	h.Write(ciphertext)
	return hex.EncodeToString(h.Sum(nil))
}
