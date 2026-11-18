package server

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
	utp "github.com/anacrolix/go-utp"
	"github.com/anacrolix/go-utp/purego"

	"bittorrent-tunnel/btawg/internal/awg"
	"bittorrent-tunnel/btawg/internal/bind"
	"bittorrent-tunnel/btawg/internal/carrier"
	"bittorrent-tunnel/btawg/internal/config"
	"bittorrent-tunnel/btawg/internal/store"
)

// TestServerClientEcho drives the hub end to end over an extended µTP
// carrier: one registered client AWG device connects through the carrier
// listener, completes the AWG handshake, and exchanges a UDP echo with a
// listener inside the server's overlay netstack.
func TestServerClientEcho(t *testing.T) {
	purego.MatrixDisableNagle = true

	st, err := store.Open(t.TempDir() + "/hub.db")
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	cfg := config.DefaultServerConfig()
	cfg.Transport = "ext-utp"
	cfg.CarrierPort = 17777

	clientPriv, clientPub, err := awg.GenerateKeyPair()
	if err != nil {
		t.Fatalf("client key: %v", err)
	}
	rec := store.ClientRecord{
		ID:      "c1",
		Name:    "smoke",
		PubKey:  clientPub,
		PrivKey: clientPriv,
		IP:      "10.77.0.2",
		PeerID:  awg.PeerID(clientPub),
		Created: time.Unix(1, 0),
	}
	if err := st.CreateClient(rec); err != nil {
		t.Fatalf("create client: %v", err)
	}

	srv, err := New(cfg, st)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { srv.Close() })
	if len(srv.InfoHash()) != 40 {
		t.Fatalf("infohash %q is not 20 bytes", srv.InfoHash())
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go srv.Run(ctx)

	// UDP echo inside the server's overlay.
	echoLn, err := srv.OverlayNet().ListenUDPAddrPort(netip.MustParseAddrPort("10.77.0.1:9000"))
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}
	t.Cleanup(func() { echoLn.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := echoLn.ReadFrom(buf)
			if err != nil {
				return
			}
			if _, err := echoLn.WriteTo(buf[:n], from); err != nil {
				return
			}
		}
	}()

	// Client AWG device over its own netstack, routed through one carrier.
	clientIP := netip.MustParseAddr("10.77.0.2")
	serverIP := netip.MustParseAddr("10.77.0.1")
	cb := bind.New()
	ct, cn, err := netstack.CreateNetTUN([]netip.Addr{clientIP}, nil, 1420)
	if err != nil {
		t.Fatalf("client netstack: %v", err)
	}
	cd := device.NewDevice(ct, cb, device.NewLogger(device.LogLevelError, "client: "))
	t.Cleanup(func() { cd.Close() })
	ccfg := config.ClientConfig{
		Version:       config.ClientVersion,
		InfoHash:      srv.InfoHash(),
		ServerPubKey:  srv.PubKey(),
		ClientPrivKey: clientPriv,
		ClientPubKey:  clientPub,
		ClientIP:      "10.77.0.2",
		Subnet:        "10.77.0.0/24",
		ServerIP:      "10.77.0.1",
		Transport:     "ext-utp",
		SocksPort:     1080,
		Profile:       config.DefaultProfile(),
	}
	if err := cd.IpcSet(awg.ClientConf(ccfg)); err != nil {
		t.Fatalf("client IpcSet: %v", err)
	}
	if err := cd.Up(); err != nil {
		t.Fatalf("client up: %v", err)
	}

	// Dial the carrier: µTP over loopback to the hub's carrier port.
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("client udp: %v", err)
	}
	t.Cleanup(func() { udp.Close() })
	sock, err := utp.NewSocketFromPacketConn(udp,
		utp.WithTargetDelay(5*time.Millisecond),
		utp.WithBufferSizes(65536, 65536))
	if err != nil {
		t.Fatalf("client utp socket: %v", err)
	}
	t.Cleanup(func() { sock.Close() })
	conn, err := sock.DialTimeout("127.0.0.1:17777", 5*time.Second)
	if err != nil {
		t.Fatalf("carrier dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	infoHash, err := ParseInfoHash(srv.InfoHash())
	if err != nil {
		t.Fatalf("parse infohash: %v", err)
	}
	peerID, err := PeerIDBytes(rec.PeerID)
	if err != nil {
		t.Fatalf("parse peer id: %v", err)
	}
	tcar, _, err := carrier.NewExtended(conn, infoHash, peerID)
	if err != nil {
		t.Fatalf("carrier handshake: %v", err)
	}
	cb.Attach(bind.Endpoint(serverIP), tcar)

	// Dial the echo socket and send a first ping: outgoing traffic is what
	// makes wireguard-go initiate the AWG handshake.
	cli, err := cn.DialUDPAddrPort(netip.AddrPortFrom(clientIP, 0), netip.MustParseAddrPort("10.77.0.1:9000"))
	if err != nil {
		t.Fatalf("client dial echo: %v", err)
	}
	t.Cleanup(func() { cli.Close() })
	if _, err := cli.WriteTo([]byte("ping"), nil); err != nil {
		t.Fatalf("echo write: %v", err)
	}

	// Wait for the authenticated AWG handshake on the client device.
	ok := false
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		state, err := cd.IpcGet()
		if err != nil {
			t.Fatalf("client IpcGet: %v", err)
		}
		var sec int64
		for _, line := range strings.Split(state, "\n") {
			if _, err := fmt.Sscanf(line, "last_handshake_time_sec=%d", &sec); err == nil && sec > 0 {
				ok = true
				break
			}
		}
		if ok {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !ok {
		t.Fatal("no authenticated AWG handshake within 10s")
	}
	if got := srv.ConnectedCount()["10.77.0.2"]; got < 1 {
		t.Fatalf("server reports %d carriers for the client, want >= 1", got)
	}

	// UDP echo through the tunnel (the session is up; this ping returns).
	if _, err := cli.WriteTo([]byte("ping"), nil); err != nil {
		t.Fatalf("echo write: %v", err)
	}
	cli.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 128)
	n, err := cli.Read(buf)
	if err != nil {
		t.Fatalf("echo read: %v", err)
	}
	if string(buf[:n]) != "ping" {
		t.Fatalf("echo = %q, want ping", buf[:n])
	}
}
