package direct

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"net"
	"net/netip"
	"testing"
	"time"
)

// A real UDP endpoint proves that punches reach it but drops µTP. Reaching
// a candidate at the UDP layer must not stop the other paths being tried.
func TestConnectFallsBackAfterVerifiedCandidateDropsUTP(t *testing.T) {
	a, b := listenTest(t), listenTest(t)
	blackhole := udpTest(t, "udp4", "127.0.0.1")
	ip := netip.MustParseAddr("127.0.0.1")
	addrA := netip.AddrPortFrom(ip, a.Port())
	addrB := netip.AddrPortFrom(ip, b.Port())
	bad := blackhole.LocalAddr().(*net.UDPAddr).AddrPort()
	key := [32]byte{81}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	lease := time.Now().Add(5 * time.Second)
	out := runConnect(ctx, a, Offer{key, true, []Candidate{{bad, "observed"}, {addrB, "lan"}}, lease})

	if err := blackhole.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	var packet [256]byte
	for {
		n, src, err := blackhole.ReadFromUDPAddrPort(packet[:])
		if err != nil {
			t.Fatalf("blackhole did not receive a µTP SYN: %v", err)
		}
		if src != addrA {
			t.Fatalf("unexpected sender %v, want %v", src, addrA)
		}
		if n >= 20 && packet[0] == 0x41 { // BEP 29 ST_SYN, version 1.
			break
		}
		if n != 89 || string(packet[:8]) != "\x00BTP2P1:" {
			continue
		}
		copy(packet[41:57], packet[25:41])
		clear(packet[25:41])
		packet[8], packet[25] = 2, 51 // responder acknowledging the initiator nonce
		tag := testPunchTag(key, packet[8:57])
		copy(packet[57:89], tag)
		if _, err := blackhole.WriteToUDPAddrPort(packet[:89], src); err != nil {
			t.Fatal(err)
		}
	}
	// b is activated only after a has committed time to the failed path.
	in := runConnect(ctx, b, Offer{key, false, []Candidate{{addrA, "lan"}}, lease})
	exchange(t, requireConnected(t, out), requireConnected(t, in), "recovered after µTP failure")
}

func TestPreviousAttemptProofCannotNominateNewStream(t *testing.T) {
	s := listenTest(t)
	remote := udpTest(t, "udp4", "127.0.0.1")
	addr := remote.LocalAddr().(*net.UDPAddr).AddrPort()
	key := [32]byte{56}
	off := Offer{key, true, []Candidate{{addr, "lan"}}, time.Now().Add(4 * time.Second)}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	first := runConnect(ctx, s, off)
	if err := remote.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	var old [89]byte
	if n, _, err := remote.ReadFromUDPAddrPort(old[:]); err != nil || n != len(old) {
		t.Fatalf("first challenge length %d: %v", n, err)
	}
	cancel()
	requireConnectError(t, first, context.Canceled)
	oldNonce := [16]byte(old[25:41])
	off.Expires = time.Now().Add(450 * time.Millisecond)
	second := runConnect(context.Background(), s, off)
	var next [256]byte
	for {
		n, src, err := remote.ReadFromUDPAddrPort(next[:])
		if err != nil {
			t.Fatalf("missing new challenge: %v", err)
		}
		if n != len(old) || [16]byte(next[25:41]) == oldNonce {
			continue
		}
		copy(old[41:57], oldNonce[:])
		clear(old[25:41])
		old[8], old[25] = 2, 13
		copy(old[57:], testPunchTag(key, old[8:57]))
		if _, err := remote.WriteToUDPAddrPort(old[:], src); err != nil {
			t.Fatal(err)
		}
		break
	}
	for {
		n, _, err := remote.ReadFromUDPAddrPort(next[:])
		if err != nil {
			if ne, ok := err.(net.Error); !ok || !ne.Timeout() {
				t.Fatal(err)
			}
			break
		}
		if n >= 20 && next[0] == 0x41 {
			t.Fatal("old authenticated proof nominated a new stream")
		}
	}
	requireConnectError(t, second, context.DeadlineExceeded)
}

func testPunchTag(secret [32]byte, message []byte) []byte {
	m := hmac.New(sha256.New, secret[:])
	m.Write([]byte("btawg/direct/pair/1"))
	m = hmac.New(sha256.New, m.Sum(nil))
	m.Write([]byte("btawg/direct/punch/1"))
	m.Write(message)
	return m.Sum(nil)
}
