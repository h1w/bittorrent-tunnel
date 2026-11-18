package server

import (
	"os"

	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
)

// filterTun is the outermost device wrapper: it enforces hub routing policy
// on every packet entering the TUN path from a peer before forwardingTun or
// the netstack see it. Placing filterTun outside forwardingTun is critical:
// packets re-injected by forwardingTun for peer-to-peer routing must also
// pass policy checks.
type filterTun struct {
	inner  tun.Device
	policy *policySnapshot
}

func (f *filterTun) File() *os.File                                 { return f.inner.File() }
func (f *filterTun) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	return f.inner.Read(bufs, sizes, offset)
}
func (f *filterTun) MTU() (int, error)                             { return f.inner.MTU() }
func (f *filterTun) Name() (string, error)                         { return f.inner.Name() }
func (f *filterTun) Events() <-chan tun.Event                      { return f.inner.Events() }
func (f *filterTun) Close() error                                  { return f.inner.Close() }
func (f *filterTun) BatchSize() int                                { return f.inner.BatchSize() }

// Write filters outbound packets from peers against the routing policy.
// Disallowed packets are dropped silently and are not passed to the inner
// device; the call still reports success for the whole batch.
func (f *filterTun) Write(bufs [][]byte, offset int) (int, error) {
	var allowed [][]byte
	for _, b := range bufs {
		packet := b[offset:]
		src, srcOK := ipv4Src(packet)
		dst, dstOK := ipv4Dst(packet)
		if !srcOK || !dstOK || !f.policy.clientCanReach(src, dst) {
			continue
		}
		allowed = append(allowed, b)
	}
	if len(allowed) == 0 {
		return len(bufs), nil
	}
	if _, err := f.inner.Write(allowed, offset); err != nil {
		return 0, err
	}
	return len(bufs), nil
}
