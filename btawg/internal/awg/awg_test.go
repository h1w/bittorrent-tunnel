package awg

import (
	"strings"
	"testing"

	"bittorrent-tunnel/btawg/internal/config"
)

func TestGenerateKeyPair(t *testing.T) {
	priv, pub, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	if len(priv) != 64 || len(pub) != 64 {
		t.Fatalf("priv len %d, pub len %d, want 64/64", len(priv), len(pub))
	}
	if priv == pub {
		t.Fatal("private key equals public key")
	}
	derived, err := DerivePubKey(priv)
	if err != nil {
		t.Fatalf("DerivePubKey: %v", err)
	}
	if derived != pub {
		t.Fatalf("DerivePubKey(priv) = %q, want %q", derived, pub)
	}
	priv2, pub2, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("second GenerateKeyPair: %v", err)
	}
	if priv2 == priv || pub2 == pub {
		t.Fatal("key pairs repeat")
	}
}

func TestClientConf(t *testing.T) {
	c := config.ClientConfig{
		ClientPrivKey: "11223344556677889900aabbccddeeff00112233",
		ServerPubKey:  "aabbccddeeff00112233445566778899aabbccdd",
		ServerIP:      "10.77.0.1",
		Profile:        config.DefaultProfile(),
	}
	got := ClientConf(c)
	for _, want := range []string{
		"private_key=11223344556677889900aabbccddeeff00112233\n",
		"public_key=aabbccddeeff00112233445566778899aabbccdd\n",
		"allowed_ip=0.0.0.0/0\n",
		"endpoint=10.77.0.1:51820\n",
		"jc=4\n", "jmin=40\n", "jmax=100\n",
		"s1=32\n", "s2=32\n", "s3=32\n", "s4=32\n",
		"h1=101\n", "h2=102\n", "h3=103\n", "h4=104\n",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("ClientConf missing %q in:\n%s", want, got)
		}
	}
}

func TestServerPeerLine(t *testing.T) {
	got := ServerPeerLine("aabbccddeeff00112233445566778899aabbccdd", "10.77.0.3")
	for _, want := range []string{
		"public_key=aabbccddeeff00112233445566778899aabbccdd\n",
		"allowed_ip=10.77.0.3/32\n",
		"endpoint=10.77.0.3:51820\n",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("ServerPeerLine missing %q in:\n%s", want, got)
		}
	}
}

func TestPeerID(t *testing.T) {
	pub := "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
	if len(pub) != 64 {
		t.Fatalf("fixture must be a 32-byte key")
	}
	id := PeerID(pub)
	if len(id) != 40 {
		t.Fatalf("PeerID len %d, want 40", len(id))
	}
	if PeerID(pub) != id {
		t.Fatal("PeerID not deterministic")
	}
	if PeerID("44556677889900aabbccddeeff00112233445566aabbccddeeff00112233") == id {
		t.Fatal("PeerID collides for different keys")
	}
	if PeerID("tooshort") != "" {
		t.Fatal("PeerID accepts malformed key, want empty string")
	}
}
