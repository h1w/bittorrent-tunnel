package purego

import (
	"net"
	"testing"
	"time"
)

func TestUDPBatchDeliversValidTailAfterSendError(t *testing.T) {
	sender, err := net.ListenUDP("udp4", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()
	receiver, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer receiver.Close()
	if err := receiver.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	s := &Socket{pc: sender, tx: newUDPWriteBatch(sender)}
	s.tx.active = true
	s.send(make([]byte, 65536), receiver.LocalAddr(), false)
	s.send([]byte("valid tail"), receiver.LocalAddr(), false)
	s.flushWrites()
	var data [16]byte
	n, _, err := receiver.ReadFromUDP(data[:])
	if err != nil || string(data[:n]) != "valid tail" {
		t.Fatalf("read %q, %v; want valid tail", data[:n], err)
	}
}

func TestPacedSocketSeparatesDataBursts(t *testing.T) {
	local := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}
	sender, err := net.ListenUDP("udp4", local)
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()
	peer, err := net.ListenUDP("udp4", local)
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	s, err := NewSocketFromPacketConn(sender, WithPacingRate(1<<20))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := peer.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	const count = 16
	sent := make(chan time.Duration, 1)
	go func() {
		s.mu.Lock()
		started := time.Now()
		defer s.mu.Unlock()
		var b [1400]byte
		for i := range count {
			b[headerSize] = byte(i)
			s.send(b[:], peer.LocalAddr(), false)
		}
		sent <- time.Since(started)
	}()
	var b [1400]byte
	for i := range count {
		n, _, err := peer.ReadFromUDP(b[:])
		if err != nil || n != len(b) || b[headerSize] != byte(i) {
			t.Fatalf("packet %d: size %d, sequence %d, error %v", i, n, b[headerSize], err)
		}
	}
	if elapsed := <-sent; elapsed < 10*time.Millisecond {
		t.Fatalf("burst was sent in %v; want at least 10 ms at 1 MiB/s", elapsed)
	}
}
