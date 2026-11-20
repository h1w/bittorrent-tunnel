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
)

const routerBufSize = 2048

var tunOffset = device.MessageTransportOffsetContent // 16 bytes of virtio/transport headroom

// packetRouter multiplexes one shared inner TUN across cryptographic engines:
// the AWG and WG devices plus one engine per authenticated TLS session.
// Outbound packets read from the inner TUN are routed to the engine that owns
// the destination overlay address. Inbound packets from an engine are
// filtered, have their source recorded, and are forwarded to the inner TUN
// (gateway or internet traffic) or injected directly into the owning engine of
// the peer (client-to-client).
type packetRouter struct {
	inner    tun.Device
	isKernel bool
	policy   *policySnapshot

	awg *engineTun
	wg  *engineTun

	routesMu sync.RWMutex
	routes   map[netip.Addr]activeRoute

	closed    chan struct{}
	closeOnce sync.Once
	closeErr  error

	pool    sync.Pool
	readWg  sync.WaitGroup
	eventWg sync.WaitGroup
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
	return r
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

// removeEngine drops the route only if this session still owns it.
func (r *packetRouter) removeEngine(e *engineTun) {
	r.routesMu.Lock()
	if r.routes[e.authSource].eng == e {
		delete(r.routes, e.authSource)
	}
	r.routesMu.Unlock()
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
	})
	return r.closeErr
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

// forget unconditionally drops the route for ip, used when a client is
// revoked or moves to a new overlay address.
func (r *packetRouter) forget(ip netip.Addr) {
	r.routesMu.Lock()
	delete(r.routes, ip)
	r.routesMu.Unlock()
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
			eng, ok := r.lookup(dst)
			if !ok {
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

// Read returns one queued packet for this engine. Client-to-client packets
// are rechecked against the current policy so revocation takes effect even
// for packets already queued.
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
			eng, active := e.router.lookup(dst)
			if !srcOK || !dstOK || !active || eng != e || !e.router.policy.downlink(src, dst, min(len(packet), len(bufs[0])-offset)) {
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

// Write receives decrypted packets from the engine, filters them, records the
// authenticated source, and forwards them toward their destination.
func (e *engineTun) Write(bufs [][]byte, offset int) (int, error) {
	var innerBufs [][]byte
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
		if e.authSource.IsValid() {
			if active, _ := e.router.lookup(src); src != e.authSource || active != e {
				continue
			}
		}
		direct := e.router.isKernel && !e.router.policy.isClient(dst) && !e.router.policy.isGateway(dst)
		now := time.Now()
		if !e.router.policy.upload(src, dst, direct, len(packet), now) {
			continue
		}
		if !e.authSource.IsValid() {
			e.router.remember(src, e, now.UnixNano())
		}
		if e.router.policy.isGateway(dst) || direct {
			innerBufs = append(innerBufs, b)
			continue
		}
		if e.router.policy.isClient(dst) {
			eng, ok := e.router.lookup(dst)
			if !ok {
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

// Close shuts down this engine's virtual view. It closes the engine's event
// stream so the owning device can finish its close sequence, but it does not
// close the shared inner TUN; the parent owns that.
func (e *engineTun) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closedFlag {
		return nil
	}
	e.closedFlag = true
	close(e.closed)
	close(e.events)
	if e.authSource.IsValid() {
		e.router.drainQueue(e.packets)
	}
	return nil
}

func (e *engineTun) MTU() (int, error)        { return e.router.inner.MTU() }
func (e *engineTun) Name() (string, error)    { return e.router.inner.Name() }
func (e *engineTun) Events() <-chan tun.Event { return e.events }
func (e *engineTun) File() *os.File           { return e.router.inner.File() }
func (e *engineTun) BatchSize() int           { return 1 }
