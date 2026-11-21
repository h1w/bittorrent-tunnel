package direct

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"bittorrent-tunnel/btawg/internal/carrier"
)

func listenTest(t *testing.T) *Socket {
	t.Helper()
	s, err := Listen(0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func udpTest(t *testing.T, network, ip string) *net.UDPConn {
	t.Helper()
	pc, err := net.ListenUDP(network, &net.UDPAddr{IP: net.ParseIP(ip)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	return pc
}

func TestObserveReportsDirectSocketEndpoint(t *testing.T) {
	s := listenTest(t)
	pc, err := carrier.NewUTPSocket(udpTest(t, "udp4", "127.0.0.1"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	served := make(chan error, 1)
	go func() { served <- ServeObserver(ctx, pc) }()

	got, err := s.Observe(ctx, pc.LocalAddr().(*net.UDPAddr).AddrPort())
	if err != nil {
		t.Fatal(err)
	}
	if want := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), s.Port()); got != want {
		t.Fatalf("observed %v, want bound endpoint %v", got, want)
	}
	cancel()
	select {
	case err := <-served:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("observer did not stop on cancellation")
	}
	// The same connection can be used to serve additional observations.
	ctx2, cancel2 := context.WithTimeout(context.Background(), time.Second)
	defer cancel2()
	go func() { served <- ServeObserver(ctx2, pc) }()
	if again, err := s.Observe(ctx2, pc.LocalAddr().(*net.UDPAddr).AddrPort()); err != nil || again != got {
		t.Fatalf("observer socket was not reusable: %v, %v", again, err)
	}
	cancel2()
	select {
	case <-served:
	case <-time.After(time.Second):
		t.Fatal("second observer did not stop on cancellation")
	}
}

func TestObserverDoesNotAmplifyOrReflectToEmbeddedAddress(t *testing.T) {
	pc := udpTest(t, "udp4", "127.0.0.1")
	client := udpTest(t, "udp4", "127.0.0.1")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	served := make(chan error, 1)
	go func() { served <- ServeObserver(ctx, pc) }()
	defer func() {
		cancel()
		<-served
	}()

	var request [43]byte
	copy(request[:8], "\x00BTOBS1?")
	copy(request[8:24], "unique challenge")
	addr := pc.LocalAddr().(*net.UDPAddr)
	for _, bad := range [][]byte{request[:24], append(request[:], 1)} {
		if _, err := client.WriteToUDP(bad, addr); err != nil {
			t.Fatal(err)
		}
	}
	// Only the exact, zero-padded nonce request gets a reply. A request
	// attempting to supply an endpoint must not reach the reflection path.
	request[24] = 4
	if _, err := client.WriteToUDP(request[:], addr); err != nil {
		t.Fatal(err)
	}
	request[24] = 0
	if _, err := client.WriteToUDP(request[:], addr); err != nil {
		t.Fatal(err)
	}
	if err := client.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	var reply [128]byte
	n, _, err := client.ReadFromUDP(reply[:])
	if err != nil {
		t.Fatal(err)
	}
	if n != len(request) || string(reply[:8]) != "\x00BTOBS1!" || string(reply[8:24]) != "unique challenge" {
		t.Fatalf("unsuitable observer reply: %x", reply[:n])
	}
	if err := client.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if n, _, err := client.ReadFromUDP(reply[:]); err == nil {
		t.Fatalf("observer also answered a malformed request: %x", reply[:n])
	} else if ne, ok := err.(net.Error); !ok || !ne.Timeout() {
		t.Fatal(err)
	}
}

func runConnect(ctx context.Context, s *Socket, o Offer) <-chan connectResult {
	result := make(chan connectResult, 1)
	go func() {
		tr, err := s.Connect(ctx, o)
		result <- connectResult{tr, err}
	}()
	return result
}

func requireConnected(t *testing.T, result <-chan connectResult) carrier.Transport {
	t.Helper()
	select {
	case r := <-result:
		if r.err != nil || r.transport == nil {
			t.Fatalf("Connect = %v, %v", r.transport, r.err)
		}
		t.Cleanup(r.transport.Wait)
		return r.transport
	case <-time.After(4 * time.Second):
		t.Fatal("Connect did not return")
		return nil
	}
}

func requireConnectError(t *testing.T, result <-chan connectResult, want error) {
	t.Helper()
	select {
	case r := <-result:
		if r.transport != nil {
			r.transport.Wait()
			t.Fatal("unexpected transport")
		}
		if !errors.Is(r.err, want) {
			t.Fatalf("Connect error = %v, want %v", r.err, want)
		}
	case <-time.After(time.Second):
		t.Fatal("Connect did not stop promptly")
	}
}

func exchange(t *testing.T, send, recv carrier.Transport, value string) {
	t.Helper()
	if err := send.Send([]byte(value)); err != nil {
		t.Fatal(err)
	}
	select {
	case packet := <-recv.Recv():
		if string(packet) != value {
			t.Fatalf("received %q, want %q", packet, value)
		}
	case <-time.After(time.Second):
		t.Fatalf("did not receive %q", value)
	}
}

func TestCrossedOffersExchangeExtendedDatagrams(t *testing.T) {
	for _, family := range []struct {
		name, ip, kind string
	}{{"IPv4", "127.0.0.1", "lan"}, {"IPv6", "::1", "ipv6"}} {
		t.Run(family.name, func(t *testing.T) {
			a, b := listenTest(t), listenTest(t)
			ip := netip.MustParseAddr(family.ip)
			if a.familyFor(ip) == nil || b.familyFor(ip) == nil {
				t.Skip("UDP6 is unavailable")
			}
			dead := udpTest(t, "udp4", "127.0.0.1").LocalAddr().(*net.UDPAddr).AddrPort()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			key := [32]byte{23}
			candidates := func(remote *Socket) []Candidate {
				return []Candidate{
					{Addr: dead, Kind: "observed"},
					{Addr: netip.AddrPortFrom(ip, remote.Port()), Kind: family.kind},
				}
			}
			lease := time.Now().Add(5 * time.Second)
			out := runConnect(ctx, a, Offer{Secret: key, Initiator: true, Candidates: candidates(b), Expires: lease})
			in := runConnect(ctx, b, Offer{Secret: key, Initiator: false, Candidates: candidates(a), Expires: lease})
			fromA, fromB := requireConnected(t, out), requireConnected(t, in)
			cancel() // The successfully returned carriers belong to the callers.
			exchange(t, fromA, fromB, "alice to bob")
			exchange(t, fromB, fromA, "bob to alice")
			// Caller cancellation must not asynchronously close the carrier.
			select {
			case <-fromA.Done():
				t.Fatal("cancelled Connect context closed the established carrier")
			default:
			}
			if err := a.Close(); err != nil {
				t.Fatal(err)
			}
			select {
			case <-fromA.Done():
			case <-time.After(time.Second):
				t.Fatal("closing Socket did not close the carrier")
			}
		})
	}
}

func TestConnectLearnsPeerSourceWithoutRemoteCandidates(t *testing.T) {
	a, b := listenTest(t), listenTest(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	key := [32]byte{67}
	lease := time.Now().Add(5 * time.Second)
	// The initiator can only learn the responder's candidate from an
	// authenticated packet that arrived from the actual UDP endpoint.
	out := runConnect(ctx, a, Offer{Secret: key, Initiator: true, Expires: lease})
	in := runConnect(ctx, b, Offer{Secret: key, Candidates: []Candidate{{Addr: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), a.Port()), Kind: "observed"}}, Expires: lease})
	exchange(t, requireConnected(t, out), requireConnected(t, in), "discovered source")
}

func TestConnectWrongKeyOrRoleCannotAttach(t *testing.T) {
	for _, tc := range []struct {
		name  string
		keyB  [32]byte
		roleB bool
	}{{"wrong key", [32]byte{2}, false}, {"reflected role", [32]byte{1}, true}} {
		t.Run(tc.name, func(t *testing.T) {
			a, b := listenTest(t), listenTest(t)
			ctx, cancel := context.WithTimeout(context.Background(), 350*time.Millisecond)
			defer cancel()
			lease := time.Now().Add(2 * time.Second)
			candidates := func(remote *Socket) []Candidate {
				return []Candidate{{Addr: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), remote.Port()), Kind: "lan"}}
			}
			out := runConnect(ctx, a, Offer{Secret: [32]byte{1}, Initiator: true, Candidates: candidates(b), Expires: lease})
			in := runConnect(ctx, b, Offer{Secret: tc.keyB, Initiator: tc.roleB, Candidates: candidates(a), Expires: lease})
			requireConnectError(t, out, context.DeadlineExceeded)
			requireConnectError(t, in, context.DeadlineExceeded)
		})
	}
}

func TestUnreachableCandidateExpiresAndActiveAttemptCancels(t *testing.T) {
	s := listenTest(t)
	remote := udpTest(t, "udp4", "127.0.0.1")
	candidate := Candidate{Addr: remote.LocalAddr().(*net.UDPAddr).AddrPort(), Kind: "lan"}
	offer := Offer{Secret: [32]byte{42}, Initiator: true, Candidates: []Candidate{candidate}, Expires: time.Now().Add(150 * time.Millisecond)}
	requireConnectError(t, runConnect(context.Background(), s, offer), context.DeadlineExceeded)

	// Start a new attempt on the same socket, observe its live outbound
	// punch, then cancel without waiting for the much longer offer expiry.
	if err := remote.SetReadDeadline(time.Now()); err != nil {
		t.Fatal(err)
	}
	var b [2048]byte
	for {
		if _, _, err := remote.ReadFromUDP(b[:]); err != nil {
			break
		}
	}
	if err := remote.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	offer.Secret = [32]byte{43}
	offer.Expires = time.Now().Add(10 * time.Second)
	result := runConnect(ctx, s, offer)
	if _, _, err := remote.ReadFromUDP(b[:]); err != nil {
		t.Fatalf("no active UDP punch: %v", err)
	}
	cancel()
	requireConnectError(t, result, context.Canceled)
}

func TestObserveRejectsResponseFromUnexpectedAddress(t *testing.T) {
	s := listenTest(t)
	observer := udpTest(t, "udp4", "127.0.0.1")
	other := udpTest(t, "udp4", "127.0.0.1")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	result := make(chan error, 1)
	go func() {
		_, err := s.Observe(ctx, observer.LocalAddr().(*net.UDPAddr).AddrPort())
		result <- err
	}()
	if err := observer.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	var b [128]byte
	n, source, err := observer.ReadFrom(b[:])
	if err != nil {
		t.Fatal(err)
	}
	if n != 43 {
		t.Fatalf("unexpected probe length %d", n)
	}
	copy(b[:8], "\x00BTOBS1!")
	b[24], b[25], b[28], b[42] = 4, 127, 1, 1
	if _, err := other.WriteTo(b[:n], source); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		t.Fatalf("forged source completed Observe: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	cancel()
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("Observe error = %v, want cancellation", err)
	}
}

func TestUnauthenticatedStreamCannotReserveActiveOffer(t *testing.T) {
	a, b := listenTest(t), listenTest(t)
	ip := netip.MustParseAddr("127.0.0.1")
	dest := func(s *Socket) netip.AddrPort { return netip.AddrPortFrom(ip, s.Port()) }
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	lease := time.Now().Add(4 * time.Second)
	key := [32]byte{7}
	// The source is present in the offer, but cannot even allocate an
	// incoming stream until it has answered an authenticated punch.
	probe := udpTest(t, "udp4", "127.0.0.1")
	in := runConnect(ctx, b, Offer{Secret: key, Candidates: []Candidate{{Addr: dest(a), Kind: "lan"}, {Addr: probe.LocalAddr().(*net.UDPAddr).AddrPort(), Kind: "lan"}}, Expires: lease})
	// Prove the offer is already in flight before trying the unauthenticated SYN.
	if err := probe.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	var packet [128]byte
	if _, _, err := probe.ReadFromUDP(packet[:]); err != nil {
		t.Fatalf("offer did not start punching: %v", err)
	}
	dialCtx, stopDial := context.WithTimeout(ctx, 150*time.Millisecond)
	defer stopDial()
	if c, err := a.v4.DialAddrContext(dialCtx, net.UDPAddrFromAddrPort(dest(b))); err == nil {
		_ = c.Close()
		t.Fatal("listener allocated µTP for an unverified candidate")
	}
	out := runConnect(ctx, a, Offer{Secret: key, Initiator: true, Candidates: []Candidate{{Addr: dest(b), Kind: "lan"}}, Expires: lease})
	exchange(t, requireConnected(t, out), requireConnected(t, in), "valid attachment")
}
