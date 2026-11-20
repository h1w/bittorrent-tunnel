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
// Each device maps to its own engine so a handshake on one mode cannot rewrite
// an active flow owned by another mode.
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
			for _, pair := range s.deviceEnginePairs() {
				state, err := pair.dev.IpcGet()
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
						s.router.observeHandshake(ip, key, pair.eng, time.Unix(sec, nsec))
					}
				}
			}
			s.applyMu.Unlock()
		}
	}
}

type deviceEnginePair struct {
	dev *device.Device
	eng *engineTun
}

// deviceEnginePairs returns every device together with the engine it feeds.
// Native AWG/WG map to their dedicated engines; each carrier mode maps to its
// own engine so handshakes update only that mode's primary route.
func (s *Server) deviceEnginePairs() []deviceEnginePair {
	out := make([]deviceEnginePair, 0, 2+len(s.modeDevs))
	if s.dev != nil {
		out = append(out, deviceEnginePair{s.dev, s.router.awg})
	}
	if s.wg != nil {
		out = append(out, deviceEnginePair{s.wg, s.router.wg})
	}
	for mode, d := range s.modeDevs {
		out = append(out, deviceEnginePair{d, s.router.engines[mode]})
	}
	return out
}
