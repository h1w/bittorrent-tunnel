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

// packetRouter multiplexes one shared inner TUN across two cryptographic
// engines: index 0 is AWG, index 1 is WG. Outbound packets read from the
// inner TUN are routed to the engine that last authenticated the destination
// overlay address. Inbound packets from an engine are filtered, have their
// source recorded, and are forwarded to the inner TUN (gateway or internet
// traffic) or injected directly into the peer engine's queue (peer-to-peer).
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
	engine int
	at     int64
}

// engineTun is the tun.Device presented to one cryptographic engine.
type engineTun struct {
	router     *packetRouter
	index      int
	packets    chan []byte
	events     chan tun.Event
	closed     chan struct{}
	mu         sync.Mutex
	closedFlag bool
}

// newPacketRouter creates a router around the shared inner TUN. isKernel is
// retained for diagnostics but does not change routing: peer-to-peer traffic
// is always routed directly between engines to avoid host-forward/firewall
// dependencies. The caller must call Up() on each assembled device
// explicitly; event fanout is handled here.
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
	r.awg = &engineTun{
		router:  r,
		index:   0,
		packets: make(chan []byte, 256),
		events:  make(chan tun.Event, 8),
		closed:  make(chan struct{}),
	}
	r.wg = &engineTun{
		router:  r,
		index:   1,
		packets: make(chan []byte, 256),
		events:  make(chan tun.Event, 8),
		closed:  make(chan struct{}),
	}

	r.readWg.Add(1)
	go r.dispatchLoop()
	r.eventWg.Add(1)
	go r.fanoutEvents()
	return r
}

// device returns the tun.Device for the requested engine: 0 for AWG, 1 for WG.
func (r *packetRouter) device(index int) *engineTun {
	if index == 0 {
		return r.awg
	}
	return r.wg
}

// close shuts down the router and the shared inner TUN once. It is safe to
// call multiple times; the parent is responsible for calling this after both
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

// forget removes any learned route for ip, used when a client or proxy
// session is revoked.
func (r *packetRouter) forget(ip netip.Addr) {
	r.routesMu.Lock()
	delete(r.routes, ip)
	r.routesMu.Unlock()
}

func (r *packetRouter) remember(ip netip.Addr, idx int) {
	r.routesMu.Lock()
	r.routes[ip] = activeRoute{engine: idx, at: time.Now().UnixNano()}
	r.routesMu.Unlock()
}

func (r *packetRouter) lookup(ip netip.Addr) (int, bool) {
	r.routesMu.RLock()
	route, ok := r.routes[ip]
	r.routesMu.RUnlock()
	return route.engine, ok
}

func (r *packetRouter) observeHandshake(raw string, idx int, when int64) {
	p, err := netip.ParsePrefix(raw)
	if err != nil || p.Bits() != 32 || !p.Addr().Is4() || !r.policy.isClient(p.Addr()) {
		return
	}
	r.routesMu.Lock()
	if when > r.routes[p.Addr()].at {
		r.routes[p.Addr()] = activeRoute{engine: idx, at: when}
	}
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
			if !r.allowedRead(src, dst) {
				continue
			}
			idx, ok := r.lookup(dst)
			if !ok {
				continue // unknown path: drop
			}
			select {
			case <-r.closed:
			case r.device(idx).packets <- bufs[i][:tunOffset+sizes[i]]:
				bufs[i] = nil // ownership transferred
			default:
				// queue full: drop
			}
		}
		for i := range bufs {
			if bufs[i] == nil {
				bufs[i] = r.pool.Get().([]byte)
			}
		}
	}
}

// allowedRead validates a packet arriving from the inner TUN. Gateway
// responses are always allowed; internet responses are allowed only when the
// destination peer is permitted internet access; peer-to-peer and other
// overlay traffic uses the normal authenticated policy.
func (r *packetRouter) allowedRead(src, dst netip.Addr) bool {
	if r.policy.isGateway(src) {
		return true
	}
	if r.policy.isClient(dst) && !r.policy.isClient(src) {
		return r.policy.packetAllowed(dst, src, true)
	}
	return r.policy.packetAllowed(src, dst, false)
}

// fanoutEvents copies events from the inner TUN to each engine's event
// channel so both devices observe MTU updates and down events. Events for an
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

// inject places a copy of packet into engine idx's inbound queue.
func (r *packetRouter) inject(idx int, packet []byte) {
	buf := r.pool.Get().([]byte)
	n := copy(buf[tunOffset:], packet)
	select {
	case <-r.closed:
		r.pool.Put(buf[:cap(buf)])
	case r.device(idx).packets <- buf[:tunOffset+n]:
	default:
		r.pool.Put(buf[:cap(buf)])
	}
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
			idx, active := e.router.lookup(dst)
			if !srcOK || !dstOK || !active || idx != e.index || !e.router.allowedRead(src, dst) {
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
		direct := e.router.isKernel && !e.router.policy.isClient(dst) && !e.router.policy.isGateway(dst)
		if !e.router.policy.packetAllowed(src, dst, direct) {
			continue
		}
		e.router.remember(src, e.index)
		if e.router.policy.isGateway(dst) || direct {
			innerBufs = append(innerBufs, b)
			continue
		}
		if e.router.policy.isClient(dst) {
			idx, ok := e.router.lookup(dst)
			if !ok {
				continue
			}
			e.router.inject(idx, packet)
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
// close the shared inner TUN; the parent does that after both engines close.
func (e *engineTun) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closedFlag {
		return nil
	}
	e.closedFlag = true
	close(e.closed)
	close(e.events)
	return nil
}

func (e *engineTun) MTU() (int, error)        { return e.router.inner.MTU() }
func (e *engineTun) Name() (string, error)    { return e.router.inner.Name() }
func (e *engineTun) Events() <-chan tun.Event { return e.events }
func (e *engineTun) File() *os.File           { return e.router.inner.File() }
func (e *engineTun) BatchSize() int           { return 1 }
