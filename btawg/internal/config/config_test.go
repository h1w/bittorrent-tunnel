package config

import (
	"reflect"
	"strings"
	"testing"
)

const wantProfileString = "jc=4\njmin=40\njmax=100\ns1=32\ns2=32\ns3=32\ns4=32\nh1=101\nh2=102\nh3=103\nh4=104\n"

// 64 hex chars = 20-byte infohash.
const testInfoHash = "0123456789abcdef0123456789abcdef01234567"

func testClientConfig() ClientConfig {
	return ClientConfig{
		Version:      1,
		InfoHash:     testInfoHash,
		ServerPubKey: "aabbccddeeff00112233445566778899aabbccdd",
		ClientPrivKey: "11223344556677889900aabbccddeeff00112233",
		ClientPubKey: "44556677889900aabbccddeeff00112233445566",
		ClientIP:     "10.77.0.2",
		Subnet:       "10.77.0.0/24",
		ServerIP:     "10.77.0.1",
		Transport:    "ext-utp",
		SocksPort:    1080,
		Profile:      DefaultProfile(),
		DHTBootstrap: []string{"router.bittorrent.com:6881"},
	}
}

func TestProfileString(t *testing.T) {
	got := DefaultProfile().String()
	if got != wantProfileString {
		t.Fatalf("DefaultProfile().String() = %q, want %q", got, wantProfileString)
	}
}

func TestImportRoundTrip(t *testing.T) {
	orig := testClientConfig()
	s, err := orig.ImportString()
	if err != nil {
		t.Fatalf("ImportString: %v", err)
	}
	if !strings.HasPrefix(s, "btawg://") {
		t.Fatalf("import string %q lacks btawg:// prefix", s)
	}
	got, err := ParseImportString(s)
	if err != nil {
		t.Fatalf("ParseImportString: %v", err)
	}
	if !reflect.DeepEqual(got, orig) {
		t.Fatalf("round trip mismatch:\n got %+v\nwant %+v", got, orig)
	}
}

func TestImportHasNoServerEndpoint(t *testing.T) {
	// The public endpoint of the server (e.g. its real-world IP:port) must
	// never leak into the import string; clients learn it via the DHT swarm.
	s, err := testClientConfig().ImportString()
	if err != nil {
		t.Fatalf("ImportString: %v", err)
	}
	externalIP := "203.0.113.7"
	if strings.Contains(s, "endpoint") {
		t.Fatalf("import string contains \"endpoint\": %q", s)
	}
	if strings.Contains(s, externalIP) {
		t.Fatalf("import string contains external IP %q", externalIP)
	}
}

func TestParseRejectsFutureVersion(t *testing.T) {
	future := testClientConfig()
	future.Version = 999
	s, err := future.ImportString()
	if err != nil {
		t.Fatalf("ImportString: %v", err)
	}
	_, err = ParseImportString(s)
	if err == nil {
		t.Fatal("ParseImportString accepted version 999, want error")
	}
	if !strings.Contains(err.Error(), "version") {
		t.Fatalf("error %q does not mention \"version\"", err)
	}
}

func TestParseRejectsBareBase64(t *testing.T) {
	s, err := testClientConfig().ImportString()
	if err != nil {
		t.Fatalf("ImportString: %v", err)
	}
	bare := strings.TrimPrefix(s, "btawg://")
	if _, err := ParseImportString(bare); err == nil {
		t.Fatal("ParseImportString accepted input without btawg:// prefix, want error")
	}
}

func TestDefaultCarrierPortIsStandardTorrentPort(t *testing.T) {
	if got := DefaultServerConfig().CarrierPort; got != 6881 {
		t.Fatalf("default CarrierPort = %d, want canonical torrent port 6881", got)
	}
}
