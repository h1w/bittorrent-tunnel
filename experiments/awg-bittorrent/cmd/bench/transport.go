package main

// transport is the carrier contract the custom Bind consumes. Every camouflage
// method (request/piece, extended, webseed) implements it: send one AWG datagram,
// receive datagrams from the peer, and close/wait for shutdown.
type transport interface {
	send([]byte) error
	recv() <-chan []byte
	doneCh() <-chan struct{}
	close()
	wait()
}
