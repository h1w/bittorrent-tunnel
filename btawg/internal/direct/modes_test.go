package direct

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"bittorrent-tunnel/btawg/internal/carrier"
	"bittorrent-tunnel/btawg/internal/config"
)

type streamOutcome struct {
	tr     carrier.Transport
	conn   net.Conn
	dialer bool
	err    error
}

func streamConnect(ctx context.Context, s *Socket, offer Offer) <-chan streamOutcome {
	ch := make(chan streamOutcome, 1)
	go func() {
		tr, conn, dialer, err := s.ConnectStream(ctx, offer)
		ch <- streamOutcome{tr, conn, dialer, err}
	}()
	return ch
}

func streamResult(t *testing.T, ch <-chan streamOutcome) streamOutcome {
	t.Helper()
	select {
	case r := <-ch:
		if r.err != nil || r.tr == nil || r.conn == nil {
			t.Fatalf("ConnectStream: %v", r.err)
		}
		t.Cleanup(r.tr.Wait)
		return r
	case <-time.After(4 * time.Second):
		t.Fatal("ConnectStream timed out")
		return streamOutcome{}
	}
}

func TestStreamModesRealLoopback(t *testing.T) {
	for _, mode := range []string{config.ModeExtUTP, config.ModeReqUTP, config.ModeExtTCP, config.ModeReqTCP, config.ModeTLSExtUTP, config.ModeTLSReqUTP, config.ModeTLSExtTCP, config.ModeTLSReqTCP} {
		t.Run(mode, func(t *testing.T) {
			tcp := mode == config.ModeExtTCP || mode == config.ModeReqTCP || mode == config.ModeTLSExtTCP || mode == config.ModeTLSReqTCP
			a, err := ListenWithTCP(0, tcp)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = a.Close() })
			b, err := ListenWithTCP(0, tcp)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = b.Close() })
			candidate := func(s *Socket) Candidate {
				port, proto := s.Port(), "udp"
				if tcp {
					port, proto = s.TCPPort(), "tcp"
				}
				return Candidate{Addr: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port), Kind: "lan", Protocol: proto}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			expires := time.Now().Add(3 * time.Second)
			x := streamConnect(ctx, a, Offer{Secret: [32]byte{1}, Initiator: true, Mode: mode, Candidates: []Candidate{candidate(b)}, Expires: expires})
			y := streamConnect(ctx, b, Offer{Secret: [32]byte{1}, Mode: mode, Candidates: []Candidate{candidate(a)}, Expires: expires})
			left, right := streamResult(t, x), streamResult(t, y)
			if left.dialer == right.dialer {
				t.Fatal("both endpoints reported the same dialer role")
			}
			if tcp {
				if _, ok := left.conn.RemoteAddr().(*net.TCPAddr); !ok {
					t.Fatalf("TCP mode used %T", left.conn.RemoteAddr())
				}
			}
			exchange(t, left.tr, right.tr, "left to right")
			exchange(t, right.tr, left.tr, "right to left")
		})
	}
}

func TestTCPReverseDialWhenOnlyInitiatorListens(t *testing.T) {
	a, err := ListenWithTCP(0, true)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := ListenWithTCP(0, false)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	expires := time.Now().Add(3 * time.Second)
	x := streamConnect(ctx, a, Offer{Secret: [32]byte{2}, Initiator: true, Mode: config.ModeExtTCP, Candidates: []Candidate{{Addr: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), b.Port()), Kind: "lan", Protocol: "tcp"}}, Expires: expires})
	y := streamConnect(ctx, b, Offer{Secret: [32]byte{2}, Mode: config.ModeExtTCP, Candidates: []Candidate{{Addr: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), a.TCPPort()), Kind: "lan", Protocol: "tcp"}}, Expires: expires})
	left, right := streamResult(t, x), streamResult(t, y)
	if left.dialer || !right.dialer {
		t.Fatal("reverse TCP roles incorrect")
	}
	exchange(t, right.tr, left.tr, "reverse")
}

func TestTCPDoesNotUseUDPCandidate(t *testing.T) {
	a, err := ListenWithTCP(0, true)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := ListenWithTCP(0, true)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	expires := time.Now().Add(time.Second)
	candidate := func(s *Socket) Candidate {
		return Candidate{Addr: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), s.Port()), Kind: "lan"}
	}
	x := streamConnect(ctx, a, Offer{Secret: [32]byte{3}, Initiator: true, Mode: config.ModeExtTCP, Candidates: []Candidate{candidate(b)}, Expires: expires})
	y := streamConnect(ctx, b, Offer{Secret: [32]byte{3}, Mode: config.ModeExtTCP, Candidates: []Candidate{candidate(a)}, Expires: expires})
	for _, ch := range []<-chan streamOutcome{x, y} {
		r := <-ch
		if r.tr != nil || r.err == nil {
			t.Fatal("TCP offer accepted UDP candidate")
		}
	}
}

func TestModeMismatchCannotAuthenticate(t *testing.T) {
	a, b := listenTest(t), listenTest(t)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	expires := time.Now().Add(time.Second)
	candidate := func(s *Socket) Candidate {
		return Candidate{Addr: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), s.Port()), Kind: "lan"}
	}
	x := streamConnect(ctx, a, Offer{Secret: [32]byte{4}, Initiator: true, Mode: config.ModeExtUTP, Candidates: []Candidate{candidate(b)}, Expires: expires})
	y := streamConnect(ctx, b, Offer{Secret: [32]byte{4}, Mode: config.ModeTLSExtUTP, Candidates: []Candidate{candidate(a)}, Expires: expires})
	for _, ch := range []<-chan streamOutcome{x, y} {
		r := <-ch
		if r.tr != nil || r.err == nil {
			t.Fatal("mismatched modes authenticated")
		}
	}
}

func TestTCPAuthenticatesUnlistedSourceAddress(t *testing.T) {
	a, err := ListenWithTCP(0, true)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := ListenWithTCP(0, true)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	expires := time.Now().Add(2 * time.Second)
	x := streamConnect(ctx, a, Offer{Secret: [32]byte{5}, Initiator: true, Mode: config.ModeReqTCP, Candidates: []Candidate{{Addr: netip.MustParseAddrPort("127.0.0.2:65500"), Protocol: "tcp"}}, Expires: expires})
	y := streamConnect(ctx, b, Offer{Secret: [32]byte{5}, Mode: config.ModeReqTCP, Candidates: []Candidate{{Addr: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), a.TCPPort()), Protocol: "tcp"}}, Expires: expires})
	left, right := streamResult(t, x), streamResult(t, y)
	exchange(t, right.tr, left.tr, "authenticated NAT source")
}

func TestTCPListenerDisabled(t *testing.T) {
	s := listenTest(t)
	if s.TCPPort() != 0 {
		t.Fatal("legacy listener unexpectedly enabled TCP")
	}
	for _, c := range s.LocalCandidates() {
		if c.Protocol == "tcp" {
			t.Fatal("advertised TCP without listener")
		}
	}
}

func TestOccupiedTCPDoesNotDisableUDP(t *testing.T) {
	ln, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	s, err := ListenWithTCP(port, true)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if s.Port() != port || s.TCPPort() != 0 {
		t.Fatalf("listener ports UDP=%d TCP=%d", s.Port(), s.TCPPort())
	}
}

func TestRejectsUnknownAndNoncanonicalModes(t *testing.T) {
	s := listenTest(t)
	for _, mode := range []string{"ext-tcp", config.ModeAWG, "unknown"} {
		tr, _, _, err := s.ConnectStream(context.Background(), Offer{Secret: [32]byte{6}, Mode: mode, Expires: time.Now().Add(time.Second)})
		if tr != nil || err == nil {
			t.Fatalf("accepted invalid carrier mode %q", mode)
		}
	}
}

func TestTCPListenerAdvertisesSeparateCandidates(t *testing.T) {
	s, err := ListenWithTCP(0, true)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if s.TCPPort() == 0 {
		t.Fatal("TCP listener has no port")
	}
	udp := make(map[netip.Addr]bool)
	tcp := make(map[netip.Addr]bool)
	for _, c := range s.LocalCandidates() {
		switch c.Protocol {
		case "", "udp":
			if c.Addr.Port() != s.Port() {
				t.Fatal("incorrect UDP port")
			}
			udp[c.Addr.Addr()] = true
		case "tcp":
			if c.Addr.Port() != s.TCPPort() {
				t.Fatal("incorrect TCP port")
			}
			tcp[c.Addr.Addr()] = true
		default:
			t.Fatalf("unexpected protocol %q", c.Protocol)
		}
	}
	for ip := range udp {
		if !tcp[ip] {
			t.Fatalf("missing TCP candidate for %s", ip)
		}
	}
}
