package purego

import (
	"encoding/binary"
	"net"
	"unsafe"

	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"
)

// trySegment sends an existing batch as one scatter/gather UDP_SEGMENT
// message. Linux splits it back into the original datagrams before delivery.
func (tx *udpWriteBatch) trySegment(messages []ipv4.Message) bool {
	if tx.noGSO || len(messages) < 2 {
		return false
	}
	size := len(messages[0].Buffers[0])
	peer, ok := messages[0].Addr.(*net.UDPAddr)
	if !ok || size == 0 || size*len(messages) > 65507 {
		return false
	}
	for i, m := range messages {
		if len(m.Buffers[0]) != size || m.Addr != peer {
			return false
		}
		tx.segments[i] = m.Buffers[0]
	}
	return tx.sendSegments(tx.segments[:len(messages)], peer, uint16(size))
}

func (tx *udpWriteBatch) sendSegments(bufs [][]byte, addr net.Addr, size uint16) bool {
	control := tx.control[:unix.CmsgSpace(2)]
	hdr := (*unix.Cmsghdr)(unsafe.Pointer(&control[0]))
	hdr.Level = unix.SOL_UDP
	hdr.Type = unix.UDP_SEGMENT
	hdr.SetLen(unix.CmsgLen(2))
	binary.NativeEndian.PutUint16(control[unix.CmsgLen(0):], size)
	tx.segment[0] = ipv4.Message{Buffers: bufs, OOB: control, Addr: addr}
	n, err := tx.pc.WriteBatch(tx.segment[:], 0)
	tx.segment[0] = ipv4.Message{}
	if err != nil {
		// A device may not support UDP segmentation. Keep ordinary UDP sends.
		tx.noGSO = true
	}
	return n == 1
}
