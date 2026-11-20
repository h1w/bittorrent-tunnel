package tunneldns

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

const defaultLookupTimeout = 10 * time.Second

// newQueryID returns a random 16-bit DNS query ID. It is overridable so tests
// can use deterministic IDs without relying on randomness.
var newQueryID = func() uint16 {
	var b [2]byte
	if _, err := rand.Read(b[:]); err != nil {
		return uint16(time.Now().UnixNano())
	}
	return binary.BigEndian.Uint16(b[:])
}

// RCodeError is returned by LookupIPv4 when the hub answers with a non-zero
// DNS response code.
type RCodeError dnsmessage.RCode

func (e RCodeError) Error() string {
	return fmt.Sprintf("tunneldns: server returned RCode %s", dnsmessage.RCode(e))
}

// LookupIPv4 asks the hub DNS-over-TCP endpoint reachable through dial for
// the IPv4 addresses of host. It sends one standard IN A query over TCP,
// using an absolute name and no local DNS resolver. The returned response is
// validated for ID, question, flags and RCODE.
func LookupIPv4(ctx context.Context, dial func(context.Context) (net.Conn, error), host string) ([]netip.Addr, error) {
	if dial == nil {
		return nil, errors.New("tunneldns: nil dial")
	}
	if host == "" {
		return nil, errors.New("tunneldns: empty host")
	}

	name, err := dnsmessage.NewName(ensureAbsolute(host))
	if err != nil {
		return nil, fmt.Errorf("tunneldns: invalid host: %w", err)
	}

	id := newQueryID()
	query := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:               id,
			RecursionDesired: true,
		},
		Questions: []dnsmessage.Question{{
			Name:  name,
			Type:  dnsmessage.TypeA,
			Class: dnsmessage.ClassINET,
		}},
	}
	qBuf, err := query.Pack()
	if err != nil {
		return nil, fmt.Errorf("tunneldns: pack query: %w", err)
	}

	qCtx, cancel := context.WithTimeout(ctx, defaultLookupTimeout)
	defer cancel()

	conn, err := dial(qCtx)
	if err != nil {
		return nil, fmt.Errorf("tunneldns: dial: %w", err)
	}
	defer conn.Close()

	stop := context.AfterFunc(qCtx, func() { conn.Close() })
	defer stop()

	if dl, ok := qCtx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	} else {
		_ = conn.SetDeadline(time.Now().Add(defaultLookupTimeout))
	}

	if err := writeTCPMessage(conn, qBuf); err != nil {
		return nil, fmt.Errorf("tunneldns: write query: %w", err)
	}

	rBuf, err := readTCPMessage(conn)
	if err != nil {
		if qCtx.Err() != nil {
			return nil, fmt.Errorf("tunneldns: lookup cancelled: %w", qCtx.Err())
		}
		return nil, fmt.Errorf("tunneldns: read response: %w", err)
	}

	return parseResponse(rBuf, id, name)
}

func parseResponse(buf []byte, id uint16, qName dnsmessage.Name) ([]netip.Addr, error) {
	var p dnsmessage.Parser
	h, err := p.Start(buf)
	if err != nil {
		return nil, fmt.Errorf("tunneldns: parse response: %w", err)
	}

	if !h.Response || h.OpCode != 0 || h.Truncated {
		return nil, errors.New("tunneldns: invalid response flags")
	}
	if h.ID != id {
		return nil, errors.New("tunneldns: response ID mismatch")
	}
	if h.RCode != dnsmessage.RCodeSuccess {
		return nil, RCodeError(h.RCode)
	}

	respQuestions, err := p.AllQuestions()
	if err != nil || len(respQuestions) != 1 {
		return nil, errors.New("tunneldns: missing response question")
	}
	respQuestion := respQuestions[0]
	if respQuestion.Type != dnsmessage.TypeA || respQuestion.Class != dnsmessage.ClassINET || respQuestion.Name != qName {
		return nil, errors.New("tunneldns: response question mismatch")
	}

	answers, err := p.AllAnswers()
	if err != nil {
		return nil, fmt.Errorf("tunneldns: parse answers: %w", err)
	}
	var addrs []netip.Addr
	for _, r := range answers {
		if r.Header.Type != dnsmessage.TypeA || r.Header.Class != dnsmessage.ClassINET {
			continue
		}
		body, ok := r.Body.(*dnsmessage.AResource)
		if !ok {
			continue
		}
		addrs = append(addrs, netip.AddrFrom4(body.A))
	}

	return addrs, nil
}

func ensureAbsolute(name string) string {
	if name == "" || name[len(name)-1] == '.' {
		return name
	}
	return name + "."
}
