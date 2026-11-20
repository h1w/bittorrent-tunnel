package client

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/tun"

	"bittorrent-tunnel/btawg/internal/carrier"
	"bittorrent-tunnel/btawg/internal/config"
	"bittorrent-tunnel/btawg/internal/iptunnel"
)

type tlsTunnel struct {
	dev    tun.Device
	cfg    *tls.Config
	life   context.Context
	cancel context.CancelFunc
	reader sync.WaitGroup
	once   sync.Once
	mu     sync.Mutex // protects TUN writes against device shutdown
	active atomic.Pointer[tlsSession]
}

type tlsSession struct {
	conn *tls.Conn
	t    carrier.Transport
}

func newTLSTunnel(dev tun.Device, cfg config.ClientConfig) (*tlsTunnel, error) {
	id, err := iptunnel.NewIdentity(cfg.ClientPrivKey, iptunnel.Client)
	if err != nil {
		return nil, err
	}
	creds, err := id.TLS(cfg.TLSServerKey)
	if err != nil {
		return nil, err
	}
	life, cancel := context.WithCancel(context.Background())
	p := &tlsTunnel{dev: dev, cfg: creds, life: life, cancel: cancel}
	p.reader.Go(func() {
		defer cancel()
		_ = iptunnel.SendPackets(dev, func(b []byte) error {
			if s := p.active.Load(); s != nil {
				if _, err := s.conn.Write(b); err != nil {
					s.t.Close()
				}
			}
			return nil
		})
	})
	p.reader.Go(func() {
		for range dev.Events() {
			// Drain kernel link events; TLS does not manage interface state.
		}
	})
	return p, nil
}

func (p *tlsTunnel) run(ctx context.Context, raw net.Conn, t carrier.Transport) error {
	defer t.Wait()
	stop := context.AfterFunc(ctx, t.Close)
	defer stop()
	conn := tls.Client(iptunnel.Stream(raw, t), p.cfg)
	if err := conn.HandshakeContext(ctx); err != nil {
		return fmt.Errorf("TLS handshake: %w", err)
	}
	if err := raw.SetDeadline(time.Time{}); err != nil {
		return err
	}
	s := &tlsSession{conn: conn, t: t}
	p.active.Store(s)
	defer p.active.CompareAndSwap(s, nil)
	fmt.Printf("btawg-client: TLS carrier connected to %s\n", raw.RemoteAddr())
	return iptunnel.ReceivePackets(tunnelWriter{p}, conn)
}

func (p *tlsTunnel) close() {
	p.once.Do(func() {
		p.cancel()
		if s := p.active.Load(); s != nil {
			s.t.Close()
		}
		p.mu.Lock()
		_ = p.dev.Close()
		p.mu.Unlock()
		p.reader.Wait()
	})
}

type tunnelWriter struct{ p *tlsTunnel }

func (w tunnelWriter) Write(bufs [][]byte, offset int) (int, error) {
	w.p.mu.Lock()
	defer w.p.mu.Unlock()
	if w.p.life.Err() != nil {
		return 0, net.ErrClosed
	}
	return w.p.dev.Write(bufs, offset)
}
