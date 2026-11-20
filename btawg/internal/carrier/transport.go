package carrier

import "io"

// BlockSize limits the frame data region including the uint16 datagram length.
// Request/piece also uses it as the fixed block length.
const BlockSize = 2048

const (
	// Let a burst of decoded packets through even when the AWG consumer
	// briefly yields on a single-core host; backpressure remains bounded.
	receiveQueuePackets = 2048
	streamReadBuffer    = 128 << 10
)

// Transport is the carrier contract the AWG Bind consumes: send one AWG
// datagram, receive datagrams from the peer, and close/wait for shutdown.
type Transport interface {
	Send([]byte) error
	Recv() <-chan []byte
	Done() <-chan struct{}
	Close()
	Wait()
}

// fullWrite writes every byte of b to c.
func fullWrite(c io.Writer, b []byte) error {
	for len(b) > 0 {
		n, err := c.Write(b)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		b = b[n:]
	}
	return nil
}
