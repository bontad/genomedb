package mesh

import (
	"encoding/base64"
	"testing"
)

func TestGenerateKeyPair(t *testing.T) {
	kp1, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	priv, err := base64.StdEncoding.DecodeString(kp1.PrivateKey)
	if err != nil || len(priv) != 32 {
		t.Fatalf("chiave privata malformata: %v (len=%d)", err, len(priv))
	}
	pub, err := base64.StdEncoding.DecodeString(kp1.PublicKey)
	if err != nil || len(pub) != 32 {
		t.Fatalf("chiave pubblica malformata: %v (len=%d)", err, len(pub))
	}

	kp2, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if kp1.PrivateKey == kp2.PrivateKey || kp1.PublicKey == kp2.PublicKey {
		t.Fatal("due generazioni successive hanno prodotto le stesse chiavi")
	}
}

func TestRenderConfig(t *testing.T) {
	iface := RenderInterfaceConfig("privkey==", "10.66.0.1/24", 51820)
	if iface == "" {
		t.Fatal("config interfaccia vuota")
	}
	peer := RenderPeerConfig("fratello", "pubkey==", "10.66.0.2/32", "203.0.113.5:51820")
	if peer == "" {
		t.Fatal("config peer vuota")
	}
}
