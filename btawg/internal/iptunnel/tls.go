// Package iptunnel carries IPv4 packets in mutually authenticated TLS over a
// BitTorrent carrier. It does not use either WireGuard engine.
package iptunnel

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"time"

	"bittorrent-tunnel/btawg/internal/carrier"
)

const MTU = 1420

const (
	Hub    = "hub"
	Client = "client"
)

// Identity is a key pair dedicated to one TLS role, not a WireGuard key.
type Identity struct {
	cert tls.Certificate
	pub  ed25519.PublicKey
}

// PublicKey derives only the expected peer pin, not a certificate.
func PublicKey(secret, role string) (string, error) {
	key, err := signingKey(secret, role)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(key[ed25519.SeedSize:]), nil
}

func signingKey(secret, role string) (ed25519.PrivateKey, error) {
	raw, err := hex.DecodeString(secret)
	if err != nil || len(raw) != 32 || (role != Hub && role != Client) {
		return nil, errors.New("invalid TLS identity input")
	}
	seed, err := hkdf.Key(sha256.New, raw, nil, "btawg/tls-ip/v1/"+role, ed25519.SeedSize)
	if err != nil {
		return nil, err
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// NewIdentity creates the certificate presented in the TLS handshake.
func NewIdentity(secret, role string) (*Identity, error) {
	key, err := signingKey(secret, role)
	if err != nil {
		return nil, err
	}
	pub := key.Public().(ed25519.PublicKey)
	now := time.Now()
	leaf := &x509.Certificate{NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(1, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, leaf, leaf, pub, key)
	if err != nil {
		return nil, err
	}
	return &Identity{cert: tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, pub: pub}, nil
}

func (i *Identity) Pin() string { return hex.EncodeToString(i.pub) }

// TLS authenticates the peer by key rather than CA or hostname. The TLS
// handshake still verifies possession of the key via CertificateVerify.
func (i *Identity) TLS(pin string) (*tls.Config, error) {
	want, err := hex.DecodeString(pin)
	if err != nil || len(want) != ed25519.PublicKeySize {
		return nil, errors.New("invalid TLS peer key; obtain a fresh import")
	}
	return &tls.Config{
		Certificates:           []tls.Certificate{i.cert},
		MinVersion:             tls.VersionTLS13,
		MaxVersion:             tls.VersionTLS13,
		ClientAuth:             tls.RequireAnyClientCert,
		SessionTicketsDisabled: true,
		InsecureSkipVerify:     true, // client-side: exact key check below replaces PKI
		VerifyConnection: func(s tls.ConnectionState) error {
			if len(s.PeerCertificates) == 1 {
				if key, ok := s.PeerCertificates[0].PublicKey.(ed25519.PublicKey); ok && bytes.Equal(key, want) {
					return nil
				}
			}
			return errors.New("unexpected TLS peer key")
		},
	}, nil
}

// Stream maps the carrier's ordered datagrams to a byte stream. TLS permits
// a single reader and a single writer simultaneously. Only the reader owns tail.
func Stream(raw net.Conn, t carrier.Transport) net.Conn {
	return &stream{Conn: raw, transport: t}
}

type stream struct {
	net.Conn
	transport carrier.Transport
	tail      []byte
}

func (s *stream) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	for len(s.tail) == 0 {
		select {
		case s.tail = <-s.transport.Recv():
		case <-s.transport.Done():
			return 0, net.ErrClosed
		}
	}
	n := copy(p, s.tail)
	s.tail = s.tail[n:]
	return n, nil
}

func (s *stream) Write(p []byte) (int, error) {
	written := 0
	for len(p) > 0 {
		n := min(len(p), carrier.BlockSize-2)
		if err := s.transport.Send(p[:n]); err != nil {
			s.transport.Close()
			return written, err
		}
		written += n
		p = p[n:]
	}
	return written, nil
}

func (s *stream) Close() error {
	s.transport.Close()
	return nil
}

// ReadPacket uses the IPv4 total-length field as the packet boundary, which
// works even when TLS records and carrier frames split or coalesce packets.
func ReadPacket(r io.Reader, buf []byte) ([]byte, error) {
	const header = 20
	if len(buf) < header {
		return nil, io.ErrShortBuffer
	}
	if _, err := io.ReadFull(r, buf[:header]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(buf[2:4]))
	ihl := int(buf[0]&0xf) * 4
	if buf[0]>>4 != 4 || ihl < header || n < ihl || n > min(len(buf), MTU) {
		return nil, errors.New("invalid IPv4 packet in TLS stream")
	}
	_, err := io.ReadFull(r, buf[header:n])
	return buf[:n], err
}
