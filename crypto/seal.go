package crypto

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"golang.org/x/crypto/scrypt"
)

// This file is a STAND-IN for hardware key sealing.
//
// A production deployment must replace LoadOrCreateRoot's storage with an
// actual call into the platform's hardware root of trust — go-tpm's
// CreatePrimary/Unseal against a TPM 2.0 (Windows/Linux), or the macOS/iOS
// Secure Enclave via the Security framework's SecKey APIs with
// kSecAttrTokenIDSecureEnclave — so the root key material is generated
// inside, and never leaves, the hardware boundary. What's implemented
// here (a scrypt-wrapped key on disk) exists purely so the rest of the
// protocol — ratchet, sharing, mutation — can be built and exercised on a
// developer machine without a TPM/Enclave dependency. Swapping it out
// changes nothing else in this codebase: every caller only ever sees a
// []byte root secret.
type sealedFile struct {
	Salt []byte `json:"salt"`
	CT   []byte `json:"ct"`
}

func sealPath(dir string) string {
	return filepath.Join(dir, "root.seal")
}

// LoadOrCreateRoot returns the node's root secret, generating and sealing
// a new one on first run. binding stands in for the hardware-bound
// unsealing material; in a real TPM/Enclave integration this parameter
// disappears — the hardware itself refuses to unseal off-device.
func LoadOrCreateRoot(dir string, binding []byte) ([]byte, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	path := sealPath(dir)
	if data, err := os.ReadFile(path); err == nil {
		var sf sealedFile
		if err := json.Unmarshal(data, &sf); err != nil {
			return nil, err
		}
		return unsealRoot(sf, binding)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	root := make([]byte, KeySize)
	if _, err := rand.Read(root); err != nil {
		return nil, err
	}
	sf, err := sealRoot(root, binding)
	if err != nil {
		return nil, err
	}
	data, err := json.Marshal(sf)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		return nil, err
	}
	return root, nil
}

func sealRoot(root, binding []byte) (sealedFile, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return sealedFile{}, err
	}
	wrapKey, err := scrypt.Key(binding, salt, 1<<15, 8, 1, KeySize)
	if err != nil {
		return sealedFile{}, err
	}
	ct, err := Encrypt(wrapKey, root, []byte("mutant-db/seal"))
	if err != nil {
		return sealedFile{}, err
	}
	return sealedFile{Salt: salt, CT: ct}, nil
}

func unsealRoot(sf sealedFile, binding []byte) ([]byte, error) {
	wrapKey, err := scrypt.Key(binding, sf.Salt, 1<<15, 8, 1, KeySize)
	if err != nil {
		return nil, err
	}
	return Decrypt(wrapKey, sf.CT, []byte("mutant-db/seal"))
}
