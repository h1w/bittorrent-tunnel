package mesh

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
)

const maxRelayHeader = 4096

func WriteRelay(w io.Writer, c Check) error {
	body, err := json.Marshal(c)
	if err != nil {
		return err
	}
	if len(body) > maxRelayHeader {
		return errors.New("relay header too large")
	}
	var buf [maxRelayHeader + 2]byte
	binary.BigEndian.PutUint16(buf[:2], uint16(len(body)))
	copy(buf[2:], body)
	n, err := w.Write(buf[:len(body)+2])
	if err == nil && n != len(body)+2 {
		return io.ErrShortWrite
	}
	return err
}

func ReadRelay(r io.Reader) (Check, error) {
	var check Check
	var buf [maxRelayHeader]byte
	if _, err := io.ReadFull(r, buf[:2]); err != nil {
		return check, err
	}
	n := int(binary.BigEndian.Uint16(buf[:2]))
	if n > len(buf) || n == 0 {
		return check, errors.New("invalid relay header")
	}
	if _, err := io.ReadFull(r, buf[:n]); err != nil {
		return check, err
	}
	return check, json.Unmarshal(buf[:n], &check)
}
