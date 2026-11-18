package main

import (
	"encoding/binary"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"
)

// pcapWriter writes a libpcap file (linktype Ethernet, IPv4) whose TCP/UDP
// headers are synthesized around the real outer transport bytes. nDPI reads
// this offline, so no live capture or root privileges are needed. Checksums
// are left zero; nDPI ignores them.
type pcapWriter struct {
	f     *os.File
	conns map[string]*tcpConn
}

type tcpConn struct {
	client netip.AddrPort
	cseq   uint32
	sseq   uint32
}

func connKey(a, b netip.AddrPort) string {
	if a.String() <= b.String() {
		return a.String() + "|" + b.String()
	}
	return b.String() + "|" + a.String()
}

var (
	captureMu sync.Mutex
	captureW  *pcapWriter
)

func startCapture(path string) error {
	captureMu.Lock()
	defer captureMu.Unlock()
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	w := &pcapWriter{f: f, conns: map[string]*tcpConn{}}
	w.globalHeader()
	captureW = w
	return nil
}

func stopCapture() {
	captureMu.Lock()
	defer captureMu.Unlock()
	if captureW != nil {
		captureW.f.Close()
		captureW = nil
	}
}

// captureTCP records one TCP payload segment. Called only for raw *net.TCPConn
// writes (the TCP variants); µTP outer bytes are captured at the UDP layer via
// captureUDP.
func captureTCP(c *net.TCPConn, payload []byte) {
	captureMu.Lock()
	defer captureMu.Unlock()
	if captureW == nil {
		return
	}
	captureW.writeTCP(addrPort(c.LocalAddr()), addrPort(c.RemoteAddr()), payload)
}

// captureUDP records one UDP datagram (µTP or bare AWG). Called from the
// network emulator's send path, the single choke point for all UDP variants.
func captureUDP(src, dst net.Addr, payload []byte) {
	captureMu.Lock()
	defer captureMu.Unlock()
	if captureW == nil {
		return
	}
	captureW.writeUDP(addrPort(src), addrPort(dst), payload)
}

func addrPort(a net.Addr) netip.AddrPort {
	if p, err := netip.ParseAddrPort(a.String()); err == nil {
		return p
	}
	return netip.MustParseAddrPort("127.0.0.1:0")
}

func (w *pcapWriter) globalHeader() {
	h := make([]byte, 24)
	binary.LittleEndian.PutUint32(h[0:], 0xa1b2c3d4)
	binary.LittleEndian.PutUint16(h[4:], 2)
	binary.LittleEndian.PutUint16(h[6:], 4)
	binary.LittleEndian.PutUint32(h[16:], 65535) // snaplen
	binary.LittleEndian.PutUint32(h[20:], 1)     // network DLT_EN10MB
	w.f.Write(h)
}

func (w *pcapWriter) record(ts time.Time, pkt []byte) {
	h := make([]byte, 16)
	binary.LittleEndian.PutUint32(h[0:], uint32(ts.Unix()))
	binary.LittleEndian.PutUint32(h[4:], uint32(ts.Nanosecond()/1000))
	binary.LittleEndian.PutUint32(h[8:], uint32(len(pkt)))
	binary.LittleEndian.PutUint32(h[12:], uint32(len(pkt)))
	w.f.Write(h)
	w.f.Write(pkt)
}

func (w *pcapWriter) eth(ip []byte) []byte {
	e := make([]byte, 14)
	e[12], e[13] = 0x08, 0x00 // IPv4
	return append(e, ip...)
}

func (w *pcapWriter) ipv4(src, dst netip.Addr, proto byte, body []byte) []byte {
	ip := make([]byte, 20)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:], uint16(20+len(body)))
	ip[8] = 64
	ip[9] = proto
	s, d := src.As4(), dst.As4()
	copy(ip[12:16], s[:])
	copy(ip[16:20], d[:])
	return append(ip, body...)
}

func (w *pcapWriter) writeUDP(src, dst netip.AddrPort, payload []byte) {
	u := make([]byte, 8)
	binary.BigEndian.PutUint16(u[0:], src.Port())
	binary.BigEndian.PutUint16(u[2:], dst.Port())
	binary.BigEndian.PutUint16(u[4:], uint16(8+len(payload)))
	ip := w.ipv4(src.Addr(), dst.Addr(), 17, append(u, payload...))
	w.record(time.Now(), w.eth(ip))
}

func (w *pcapWriter) tcpSegment(src, dst netip.AddrPort, seq, ack uint32, flags byte, opts, payload []byte) {
	hlen := 20 + len(opts)
	t := make([]byte, hlen)
	binary.BigEndian.PutUint16(t[0:], src.Port())
	binary.BigEndian.PutUint16(t[2:], dst.Port())
	binary.BigEndian.PutUint32(t[4:], seq)
	binary.BigEndian.PutUint32(t[8:], ack)
	t[12] = byte(hlen/4) << 4
	t[13] = flags
	binary.BigEndian.PutUint16(t[14:], 64240)
	copy(t[20:], opts)
	ip := w.ipv4(src.Addr(), dst.Addr(), 6, append(t, payload...))
	w.record(time.Now(), w.eth(ip))
}

func (w *pcapWriter) writeTCP(src, dst netip.AddrPort, payload []byte) {
	key := connKey(src, dst)
	st := w.conns[key]
	if st == nil {
		st = &tcpConn{client: src, cseq: 1, sseq: 1000}
		w.conns[key] = st
		mss := []byte{2, 4, 0x05, 0xB4} // MSS=1460, so the SYN is not a bare scanner signature
		w.tcpSegment(src, dst, st.cseq, 0, 0x02, mss, nil)       // SYN
		st.cseq++
		w.tcpSegment(dst, src, st.sseq, st.cseq, 0x12, mss, nil) // SYN+ACK
		st.sseq++
		w.tcpSegment(src, dst, st.cseq, st.sseq, 0x10, nil, nil) // ACK
	}
	var seq, ack uint32
	if src == st.client {
		seq, ack = st.cseq, st.sseq
		st.cseq += uint32(len(payload))
	} else {
		seq, ack = st.sseq, st.cseq
		st.sseq += uint32(len(payload))
	}
	w.tcpSegment(src, dst, seq, ack, 0x18, nil, payload) // PSH|ACK
}
