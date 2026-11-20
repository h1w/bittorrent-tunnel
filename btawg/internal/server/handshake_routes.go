package server

import (
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/device"
)

// refreshHandshakeRoutes learns routes for idle peers without trusting carrier
// headers. The device only publishes a handshake timestamp after authentication.
func (s *Server) refreshHandshakeRoutes() {
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	flush := time.NewTicker(15 * time.Second)
	defer flush.Stop()
	for {
		select {
		case <-s.closed:
			return
		case <-flush.C:
			if err := s.flushTraffic(); err != nil {
				log.Printf("btawg-server: save traffic: %v", err)
			}
		case <-tick.C:
			s.applyMu.Lock()
			for i, d := range []*device.Device{s.dev, s.wg} {
				state, err := d.IpcGet()
				if err != nil {
					continue
				}
				_, peers, _ := strings.Cut(state, "\npublic_key=")
				for block := range strings.SplitSeq(peers, "\npublic_key=") {
					key, _, _ := strings.Cut(block, "\n")
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
						eng := s.router.awg
						if i == 1 {
							eng = s.router.wg
						}
						s.router.observeHandshake(ip, key, eng, time.Unix(sec, nsec))
					}
				}
			}
			s.applyMu.Unlock()
		}
	}
}
