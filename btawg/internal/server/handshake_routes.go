package server

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/device"
)

// refreshHandshakeRoutes learns routes for idle peers without trusting carrier
// headers. The device only publishes a handshake timestamp after authentication.
func (s *Server) refreshHandshakeRoutes(ctx context.Context) {
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			for i, d := range []*device.Device{s.dev, s.wg} {
				state, err := d.IpcGet()
				if err != nil {
					continue
				}
				for block := range strings.SplitSeq(state, "\npublic_key=") {
					var sec, nsec int64
					var ip string
					for line := range strings.SplitSeq(block, "\n") {
						if v, ok := strings.CutPrefix(line, "last_handshake_time_sec="); ok {
							sec, _ = strconv.ParseInt(v, 10, 64)
						}
						if v, ok := strings.CutPrefix(line, "last_handshake_time_nsec="); ok {
							nsec, _ = strconv.ParseInt(v, 10, 64)
						}
						if v, ok := strings.CutPrefix(line, "allowed_ip="); ok {
							ip = v
						}
					}
					if sec > 0 {
						s.router.observeHandshake(ip, i, time.Unix(sec, nsec).UnixNano())
					}
				}
			}
		}
	}
}
