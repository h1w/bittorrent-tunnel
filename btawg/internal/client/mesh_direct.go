package client

import (
	"context"
	"fmt"
	"log"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun"

	"bittorrent-tunnel/btawg/internal/awg"
	"bittorrent-tunnel/btawg/internal/bind"
	"bittorrent-tunnel/btawg/internal/dht"
	"bittorrent-tunnel/btawg/internal/direct"
	"bittorrent-tunnel/btawg/internal/mesh"
	"bittorrent-tunnel/btawg/internal/portmap"
)

type directPeer struct {
	secret     [32]byte
	until      atomic.Int64
	stop       context.CancelFunc
	candidates []mesh.Candidate
	ready      atomic.Bool
	done       chan struct{}
}

func (n *meshNode) run(p2p, autoMap bool, port uint16, endpoint string, exitRunning *atomic.Int32) {
	var sock *direct.Socket
	var private, public string
	var err error
	if p2p && n.owner.shared != nil {
		private, public, err = awg.GenerateKeyPair()
		if err == nil {
			sock, err = direct.Listen(port)
		}
		if err != nil {
			log.Printf("btawg-client: direct socket: %v", err)
		}
		if err != nil {
			public = ""
		}
	}
	if sock != nil {
		defer sock.Close()
	}
	var mapped atomic.Pointer[[]netip.AddrPort]
	var wg sync.WaitGroup
	defer wg.Wait()
	if sock != nil && autoMap {
		wg.Go(func() {
			if err := portmap.Run(n.ctx, sock.Port(), func(aps []netip.AddrPort) { next := slices.Clone(aps); mapped.Store(&next) }); err != nil {
				log.Printf("btawg-client: port mapping: %v", err)
			}
		})
	}
	var requested map[netip.Addr]time.Time
	if sock != nil {
		requested = make(map[netip.Addr]time.Time)
		n.owner.shared.enableDirect(n.owner.cfg)
	}
	active := make(map[netip.Addr]*directPeer)
	defer func() {
		for _, p := range active {
			p.stop()
		}
	}()
	var observer netip.AddrPort
	if sock != nil {
		observer = n.observerEndpoint()
	}
	var observed netip.AddrPort
	var expiry time.Time
	for n.ctx.Err() == nil {
		reg := mesh.Registration{DirectKey: public, Egress: exitRunning.Load() > 0}
		if sock != nil {
			if ep, err := netip.ParseAddrPort(endpoint); err == nil {
				kind := "public"
				if ep.Addr().Is6() {
					kind = "ipv6"
				}
				reg.Candidates = append(reg.Candidates, mesh.Candidate{Addr: ep, Kind: kind})
			}
			now := time.Now()
			for addr, until := range requested {
				if !now.Before(until) {
					delete(requested, addr)
				}
			}
			for i := 0; i < cap(n.owner.shared.directWanted); i++ {
				select {
				case addr := <-n.owner.shared.directWanted:
					if len(requested) < mesh.MaxPeers || !requested[addr].IsZero() {
						requested[addr] = now.Add(mesh.Lease * 2)
					}
				default:
					goto wantsReady
				}
			}
		wantsReady:
			for addr := range requested {
				reg.Want = append(reg.Want, addr)
			}
			for _, c := range sock.LocalCandidates() {
				reg.Candidates = append(reg.Candidates, mesh.Candidate{Addr: c.Addr, Kind: c.Kind})
			}
			if candidates := mapped.Load(); candidates != nil {
				for _, ap := range *candidates {
					reg.Candidates = append(reg.Candidates, mesh.Candidate{Addr: ap, Kind: "mapped"})
				}
			}
			if time.Now().After(expiry) {
				if !observer.IsValid() {
					observer = n.observerEndpoint()
				}
				if observer.IsValid() {
					ctx, cancel := context.WithTimeout(n.ctx, 500*time.Millisecond)
					observed, _ = sock.Observe(ctx, observer)
					cancel()
				}
				expiry = time.Now().Add(8 * time.Second)
			}
			if observed.IsValid() {
				reg.Candidates = append(reg.Candidates, mesh.Candidate{Addr: observed, Kind: "observed"})
			}
			if len(reg.Candidates) > 32 {
				reg.Candidates = reg.Candidates[:32]
			}
		}
		reply, err := n.register(reg)
		if sock != nil && (err == nil || err == errMeshDenied) {
			for addr, p := range active {
				i := slices.IndexFunc(reply.Pairs, func(o mesh.Pair) bool { return o.IP == addr && o.Secret == p.secret })
				if i < 0 {
					p.stop()
					continue
				}
				if !p.ready.Load() && !slices.Equal(p.candidates, reply.Pairs[i].Candidates) {
					p.stop()
					continue
				}
				p.until.Store(reply.Pairs[i].Expires.UnixNano())
			}
			for _, offer := range reply.Pairs {
				if _, ok := active[offer.IP]; ok {
					continue
				}
				ctx, stop := context.WithCancel(n.ctx)
				p := &directPeer{secret: offer.Secret, candidates: offer.Candidates, stop: stop, done: make(chan struct{})}
				p.until.Store(offer.Expires.UnixNano())
				active[offer.IP] = p
				wg.Go(func() { defer close(p.done); defer stop(); n.runPeer(ctx, sock, private, offer, p) })
			}
		}
		for addr, p := range active {
			select {
			case <-p.done:
				delete(active, addr)
			default:
			}
		}
		select {
		case <-n.ctx.Done():
			return
		case <-time.After(mesh.Poll):
		}
	}
}

func (n *meshNode) observerEndpoint() netip.AddrPort {
	cfg := n.owner.cfg
	if ep, err := netip.ParseAddrPort(cfg.CarrierEndpoint); err == nil {
		return ep
	}
	if cfg.InfoHash == "" {
		return netip.AddrPort{}
	}
	hash, err := awg.InfoHashBytes(cfg.InfoHash)
	if err != nil {
		return netip.AddrPort{}
	}
	ctx, cancel := context.WithTimeout(n.ctx, 900*time.Millisecond)
	defer cancel()
	if peers, err := dht.Discover(ctx, hash, cfg.DHTBootstrap); err == nil && len(peers) > 0 {
		return peers[0]
	}
	return netip.AddrPort{}
}

func (n *meshNode) runPeer(ctx context.Context, sock *direct.Socket, private string, p mesh.Pair, peer *directPeer) {
	if !p.IP.Is4() || len(p.Key) != 64 {
		return
	}
	var key device.NoisePublicKey
	if key.FromHex(p.Key) != nil {
		return
	}
	offer := direct.Offer{Secret: p.Secret, Initiator: p.Initiator, Expires: p.Expires}
	for _, c := range p.Candidates {
		offer.Candidates = append(offer.Candidates, direct.Candidate{Addr: c.Addr, Kind: c.Kind})
	}
	tr, err := sock.Connect(ctx, offer)
	if err != nil {
		return
	}
	defer tr.Wait()
	shared := n.owner.shared
	path := shared.newPath()
	path.directLife = ctx
	path.directUntil = &peer.until
	defer path.Close()
	local := netip.MustParseAddr(n.owner.cfg.ClientIP)
	link := &directTun{tunPath: path, local: local, peer: p.IP}
	b := bind.New()
	level := device.LogLevelError
	if os.Getenv("BTAWG_AWG_VERBOSE") != "" {
		level = device.LogLevelVerbose
	}
	d := device.NewDevice(link, b, device.NewLogger(level, "btawg-p2p: "))
	defer d.Close()
	ep := bind.Endpoint(p.IP)
	cfg := fmt.Sprintf("private_key=%s\n%spublic_key=%s\nallowed_ip=%s/32\nendpoint=%s\n", private, n.owner.cfg.Profile.String(), p.Key, p.IP, ep.DstToString())
	if err := d.IpcSet(cfg); err != nil {
		log.Printf("btawg-client: direct device config: %v", err)
		return
	}
	if err := d.Up(); err != nil {
		log.Printf("btawg-client: direct device: %v", err)
		return
	}
	b.Attach(ep, tr)
	// The responder learns the session on the first initiation and confirms
	// it on the first encrypted keepalive. Do not race two AWG handshakes.
	if p.Initiator {
		if err := d.IpcSet(fmt.Sprintf("public_key=%s\npersistent_keepalive_interval=5\n", p.Key)); err != nil {
			return
		}
		if wg := d.LookupPeer(key); wg != nil {
			wg.SendKeepalive()
		}
	}
	ready := false
	defer func() {
		if ready {
			shared.removeDirect(p.IP, path)
		}
	}()
	tick := time.NewTicker(200 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tr.Done():
			return
		case <-tick.C:
		}
		now := time.Now()
		if now.UnixNano() >= peer.until.Load() {
			return
		}
		if !ready {
			status, err := d.IpcGet()
			if err != nil {
				return
			}
			for line := range strings.SplitSeq(status, "\n") {
				if secs, ok := strings.CutPrefix(line, "last_handshake_time_sec="); ok && secs != "0" {
					if ctx.Err() != nil {
						return
					}
					shared.setDirect(p.IP, path)
					ready = true
					peer.ready.Store(true)
					break
				}
			}
			if !ready && !now.Before(p.Expires) {
				return
			}
		}
	}
}

// AWG only accepts the peer's overlay /32; this also rejects any packet
// destined elsewhere, including attempts to use this device as a router.
type directTun struct {
	*tunPath
	local, peer netip.Addr
}

var _ tun.Device = (*directTun)(nil)

func (t *directTun) Write(bufs [][]byte, offset int) (int, error) {
	if !t.validDirect() {
		return len(bufs), nil
	}
	for _, b := range bufs {
		if len(b) < offset+20 {
			continue
		}
		p := b[offset:]
		if p[0]>>4 != 4 || netip.AddrFrom4([4]byte(p[12:16])) != t.peer || netip.AddrFrom4([4]byte(p[16:20])) != t.local {
			continue
		}
		if _, err := t.tunPath.Write([][]byte{b}, offset); err != nil {
			return 0, err
		}
	}
	return len(bufs), nil
}
