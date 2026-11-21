package server

import (
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
	"golang.org/x/net/ipv4"

	"bittorrent-tunnel/btawg/internal/tunneldns"
)

const routerBufSize = 2048

var tunOffset = device.MessageTransportOffsetContent // 16 bytes of virtio/transport headroom

// packetRouter multiplexes one shared inner TUN across cryptographic engines:
// one AWG device per BitTorrent carrier mode, separate native AWG and WG
// devices, and one engine per authenticated TLS session. Outbound packets read
// from the inner TUN are routed to the engine that owns the destination overlay
// address, with per-flow reverse routing taking precedence over the per-IP
// primary route. Inbound packets from an engine are filtered, have their source
// recorded, and are forwarded to the inner TUN (gateway or internet traffic) or
// injected directly into the owning engine of the peer (client-to-client).
type packetRouter struct {
	inner    tun.Device
	isKernel bool
	policy   *policySnapshot

	awg     *engineTun
	wg      *engineTun
	engines map[string]*engineTun // keyed by canonical carrier mode

	routesMu sync.RWMutex
	routes   map[netip.Addr]activeRoute

	flows *flowTable

	closed    chan struct{}
	closeOnce sync.Once
	closeErr  error

	pool    sync.Pool
	readWg  sync.WaitGroup
	eventWg sync.WaitGroup
	flowWg  sync.WaitGroup
}

type activeRoute struct {
	eng *engineTun
	at  int64
}

// engineTun is the tun.Device presented to one cryptographic engine. For the
// AWG and WG devices authSource is zero and the engine is trusted to assert
// the source address; a TLS session sets authSource to its enrolled overlay IP
// so a client cannot spoof another client's source.
type engineTun struct {
	router     *packetRouter
	authSource netip.Addr
	packets    chan []byte
	events     chan tun.Event
	closed     chan struct{}
	mu         sync.Mutex
	closedFlag bool
}

// newPacketRouter creates a router around the shared inner TUN. Peer traffic
// moves directly between engines; only gateway and routed egress use the TUN.
func newPacketRouter(inner tun.Device, isKernel bool, policy *policySnapshot) *packetRouter {
	r := &packetRouter{
		inner:    inner,
		isKernel: isKernel,
		policy:   policy,
		routes:   make(map[netip.Addr]activeRoute),
		engines:  make(map[string]*engineTun),
		flows:    newFlowTable(),
		closed:   make(chan struct{}),
	}
	r.pool.New = func() interface{} {
		return make([]byte, routerBufSize)
	}
	r.awg = r.newEngine(netip.Addr{})
	r.wg = r.newEngine(netip.Addr{})

	r.readWg.Add(1)
	go r.dispatchLoop()
	r.eventWg.Add(1)
	go r.fanoutEvents()
	r.flowWg.Add(1)
	go r.flowCleanupLoop()
	return r
}

// engineForMode returns the engine associated with a canonical carrier mode,
// creating it on first use. The caller must not use this concurrently with
// mode creation during server startup.
func (r *packetRouter) engineForMode(mode string) *engineTun {
	r.routesMu.Lock()
	defer r.routesMu.Unlock()
	e, ok := r.engines[mode]
	if !ok {
		e = r.newEngine(netip.Addr{})
		r.engines[mode] = e
	}
	return e
}

// newEngine creates a queue. For TLS, authSource pins the enrolled IP.
func (r *packetRouter) newEngine(authSource netip.Addr) *engineTun {
	e := &engineTun{
		router:     r,
		authSource: authSource,
		packets:    make(chan []byte, 256),
		events:     make(chan tun.Event, 8),
		closed:     make(chan struct{}),
	}
	return e
}

// removeEngine drops the route only if this session still owns it and
// invalidates any pinned flows for the engine.
func (r *packetRouter) removeEngine(e *engineTun) {
	r.routesMu.Lock()
	if r.routes[e.authSource].eng == e {
		delete(r.routes, e.authSource)
	}
	r.routesMu.Unlock()
	r.flows.removeForEngine(e)
}

// close shuts down the router and the shared inner TUN once. It is safe to
// call multiple times; the parent is responsible for calling this after the
// engine devices have been closed.
func (r *packetRouter) close() error {
	r.closeOnce.Do(func() {
		close(r.closed)
		r.closeErr = r.inner.Close()
		r.readWg.Wait()
		r.eventWg.Wait()
		r.drainQueue(r.awg.packets)
		r.drainQueue(r.wg.packets)
		for _, e := range r.engines {
			r.drainQueue(e.packets)
		}
		r.flowWg.Wait()
	})
	return r.closeErr
}

func (r *packetRouter) flowCleanupLoop() {
	defer r.flowWg.Done()
	tick := time.NewTicker(30 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-tick.C:
			r.flows.cleanup(time.Now())
		case <-r.closed:
			return
		}
	}
}

func (r *packetRouter) remember(ip netip.Addr, e *engineTun, now int64) {
	r.routesMu.Lock()
	r.routes[ip] = activeRoute{eng: e, at: now}
	r.routesMu.Unlock()
}

func (r *packetRouter) lookup(ip netip.Addr) (*engineTun, bool) {
	r.routesMu.RLock()
	route, ok := r.routes[ip]
	r.routesMu.RUnlock()
	return route.eng, ok
}

func (r *packetRouter) observeHandshake(raw, key string, e *engineTun, at time.Time) {
	p, err := netip.ParsePrefix(raw)
	if err != nil || p.Bits() != 32 || !p.Addr().Is4() || !r.policy.handshake(p.Addr(), key, at) {
		return
	}
	when := at.UnixNano()
	r.routesMu.Lock()
	if when > r.routes[p.Addr()].at {
		r.routes[p.Addr()] = activeRoute{eng: e, at: when}
	}
	r.routesMu.Unlock()
}

// forget unconditionally drops the route and all pinned flows for ip, used
// when a client is revoked or moves to a new overlay address.
func (r *packetRouter) forget(ip netip.Addr) {
	r.routesMu.Lock()
	delete(r.routes, ip)
	r.routesMu.Unlock()
	r.flows.removeForIP(ip)
}

// dispatchLoop reads batches from the shared inner TUN and routes each valid
// IPv4 packet to the engine responsible for its destination. Unknown paths
// and disallowed packets are dropped; buffers are returned to the pool.
func (r *packetRouter) dispatchLoop() {
	defer r.readWg.Done()

	batch := r.inner.BatchSize()
	if batch < 1 {
		batch = 1
	}
	bufs := make([][]byte, batch)
	sizes := make([]int, batch)
	for i := range bufs {
		bufs[i] = r.pool.Get().([]byte)
	}
	defer func() {
		for _, b := range bufs {
			if b != nil {
				r.pool.Put(b[:cap(b)])
			}
		}
	}()

	for {
		n, err := r.inner.Read(bufs, sizes, tunOffset)
		if err != nil {
			return
		}
		now := time.Now()
		for i := range n {
			if sizes[i] < 1 || sizes[i] > len(bufs[i])-tunOffset {
				continue
			}
			packet := bufs[i][tunOffset : tunOffset+sizes[i]]
			src, srcOK := ipv4Src(packet)
			dst, dstOK := ipv4Dst(packet)
			if !srcOK || !dstOK {
				continue
			}
			if !r.policy.downlink(src, dst, 0) {
				continue
			}
			eng := r.lookupDestinationEngine(src, dst, packet, now)
			if eng == nil {
				continue // unknown path: drop
			}
			if eng.enqueue(bufs[i][:tunOffset+sizes[i]]) {
				bufs[i] = nil // ownership transferred
			}
		}
		for i := range bufs {
			if bufs[i] == nil {
				bufs[i] = r.pool.Get().([]byte)
			}
		}
	}
}

// lookupDestinationEngine selects the engine that should receive a packet
// addressed to dst. Per-flow reverse routing takes precedence over the per-IP
// primary route. The returned engine is nil when no path is known.
func (r *packetRouter) lookupDestinationEngine(src, dst netip.Addr, packet []byte, now time.Time) *engineTun {
	if fragKey, ok := fragmentKeyFromPacket(packet); ok {
		if eng, ok := r.flows.lookupFragment(fragKey, now); ok {
			return eng
		}
	}
	if key, ok := flowKeyFromPacket(packet); ok {
		if eng, ok := r.flows.lookup(key, now); ok {
			return eng
		}
	}
	if eng, ok := r.lookup(dst); ok {
		return eng
	}
	return nil
}

// fanoutEvents copies events from the inner TUN to each engine's event
// channel so all devices observe MTU updates and down events. Events for an
// already-closed engine are dropped.
func (r *packetRouter) fanoutEvents() {
	defer r.eventWg.Done()
	src := r.inner.Events()
	if src == nil {
		return
	}
	for {
		select {
		case ev, ok := <-src:
			if !ok {
				return
			}
			r.awg.sendEvent(ev)
			r.wg.sendEvent(ev)
			r.routesMu.RLock()
			engines := make([]*engineTun, 0, len(r.engines))
			for _, e := range r.engines {
				engines = append(engines, e)
			}
			r.routesMu.RUnlock()
			for _, e := range engines {
				e.sendEvent(ev)
			}
		case <-r.closed:
			return
		}
	}
}

func (e *engineTun) sendEvent(ev tun.Event) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closedFlag {
		return
	}
	select {
	case e.events <- ev:
	default:
	}
}

// inject places a copy of packet into an engine's inbound queue.
func (r *packetRouter) inject(e *engineTun, packet []byte) {
	buf := r.pool.Get().([]byte)
	n := copy(buf[tunOffset:], packet)
	if !e.enqueue(buf[:tunOffset+n]) {
		r.pool.Put(buf[:cap(buf)])
	}
}

func (e *engineTun) enqueue(p []byte) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closedFlag {
		return false
	}
	select {
	case <-e.router.closed:
	case e.packets <- p:
		return true
	default:
	}
	return false
}

func (r *packetRouter) drainQueue(ch <-chan []byte) {
	for {
		select {
		case p := <-ch:
			r.pool.Put(p[:cap(p)])
		default:
			return
		}
	}
}

// Read returns one queued packet for this engine. Packets are accepted if
// this engine owns the destination according to either the per-flow reverse
// route or the per-IP primary route. Client-to-client packets are rechecked
// against the current policy so revocation takes effect even for packets
// already queued.
func (e *engineTun) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	if len(bufs) == 0 || len(sizes) < len(bufs) || len(bufs[0]) <= offset {
		return 0, errShortBuffer
	}
	for {
		select {
		case <-e.closed:
			return 0, net.ErrClosed
		case <-e.router.closed:
			return 0, net.ErrClosed
		case p := <-e.packets:
			if len(p) <= tunOffset {
				e.router.pool.Put(p[:cap(p)])
				continue
			}
			packet := p[tunOffset:]
			if len(packet) > len(bufs[0])-offset {
				e.router.pool.Put(p[:cap(p)])
				return 0, errShortBuffer
			}
			src, srcOK := ipv4Src(packet)
			dst, dstOK := ipv4Dst(packet)
			if !srcOK || !dstOK {
				e.router.pool.Put(p[:cap(p)])
				continue
			}
			now := time.Now()
			owner := e.router.lookupDestinationEngine(src, dst, packet, now)
			if owner != e {
				// Primary route may have moved; drop stale packet rather than
				// deliver to the wrong engine. The sender will retry through
				// the current owner.
				e.router.pool.Put(p[:cap(p)])
				continue
			}
			if !e.router.policy.downlink(src, dst, min(len(packet), len(bufs[0])-offset)) {
				e.router.pool.Put(p[:cap(p)])
				continue
			}
			n := copy(bufs[0][offset:], packet)
			sizes[0] = n
			e.router.pool.Put(p[:cap(p)])
			return 1, nil
		}
	}
}

// Write receives decrypted packets from the engine, filters them, pins the
// authenticated reverse flow to this engine, and forwards them toward their
// destination.
func (e *engineTun) Write(bufs [][]byte, offset int) (int, error) {
	var innerBufs [][]byte
	now := time.Now()
	for _, b := range bufs {
		if len(b) < offset+ipv4.HeaderLen {
			continue
		}
		packet := b[offset:]
		src, srcOK := ipv4Src(packet)
		dst, dstOK := ipv4Dst(packet)
		if !srcOK || !dstOK {
			continue
		}
		if e.authSource.IsValid() && src != e.authSource {
			continue
		}
		direct := e.router.isKernel && !e.router.policy.isClient(dst) && !e.router.policy.isGateway(dst)
		if !e.router.policy.upload(src, dst, direct, len(packet), now) {
			continue
		}
		// Pin the reverse flow so replies return to this engine. This is the
		// only moment a flow's ownership is established; route changes and
		// later handshakes cannot steal an active flow.
		if !e.pinReverseFlow(packet, now) || !e.router.policy.isGateway(dst) {
			e.router.remember(src, e, now.UnixNano())
		}
		if e.router.policy.isGateway(dst) || direct {
			innerBufs = append(innerBufs, b)
			continue
		}
		if e.router.policy.isClient(dst) {
			eng := e.router.lookupClientEngine(src, dst, packet, now)
			if eng == nil {
				continue
			}
			e.router.inject(eng, packet)
			continue
		}
	}
	if len(innerBufs) > 0 {
		if _, err := e.router.inner.Write(innerBufs, offset); err != nil {
			return 0, err
		}
	}
	return len(bufs), nil
}

// pinReverseFlow records that return traffic for packet belongs to this
// engine. For fragmented packets the IP ID is also pinned so all fragments
// follow the same path.
// It reports a DNS flow, which already has a return path and must not make
// periodic health probes the preferred route for unrelated traffic.
func (e *engineTun) pinReverseFlow(packet []byte, now time.Time) (dns bool) {
	if key, ok := flowKeyFromPacket(packet); ok {
		e.router.flows.pin(key.reverse(), e, now)
		dns = key.proto == 6 && key.b == tunneldns.Port
	}
	if fragKey, ok := fragmentKeyFromPacket(packet); ok {
		e.router.flows.pinFragment(fragKey, e)
	}
	return dns
}

// lookupClientEngine selects the engine that should receive a
// client-to-client packet addressed to dst. Per-flow routing takes precedence
// (the destination may have initiated to the source), falling back to the
// destination's current primary route.
func (r *packetRouter) lookupClientEngine(src, dst netip.Addr, packet []byte, now time.Time) *engineTun {
	if fragKey, ok := fragmentKeyFromPacket(packet); ok {
		if eng, ok := r.flows.lookupFragment(fragKey, now); ok {
			return eng
		}
	}
	if key, ok := flowKeyFromPacket(packet); ok {
		if eng, ok := r.flows.lookup(key, now); ok {
			return eng
		}
	}
	if eng, ok := r.lookup(dst); ok {
		return eng
	}
	return nil
}

// Close shuts down this engine's virtual view. It closes the engine's event
// stream so the owning device can finish its close sequence, but it does not
// close the shared inner TUN; the parent owns that.
func (e *engineTun) Close() error {
	e.mu.Lock()
	if e.closedFlag {
		e.mu.Unlock()
		return nil
	}
	e.closedFlag = true
	close(e.closed)
	close(e.events)
	if e.authSource.IsValid() {
		e.router.drainQueue(e.packets)
	}
	e.mu.Unlock()
	e.router.flows.removeForEngine(e)
	return nil
}

func (e *engineTun) MTU() (int, error)        { return e.router.inner.MTU() }
func (e *engineTun) Name() (string, error)    { return e.router.inner.Name() }
func (e *engineTun) Events() <-chan tun.Event { return e.events }
func (e *engineTun) File() *os.File           { return e.router.inner.File() }
func (e *engineTun) BatchSize() int           { return 1 }
