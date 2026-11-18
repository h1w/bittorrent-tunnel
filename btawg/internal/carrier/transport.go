package carrier

import "io"

// BlockSize is the fixed data region of every BitTorrent message that carries
// AWG traffic: a uint16 length prefix, the AWG datagram, and cryptographically
// random tail padding so each message reads as high-entropy content.
const BlockSize = 2048

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
