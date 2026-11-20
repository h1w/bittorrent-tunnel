package store

import (
	"encoding/binary"
	"fmt"

	bolt "go.etcd.io/bbolt"
)

var bucketTraffic = []byte("traffic")

// Traffic counts inner IP bytes from the client's perspective and records the
// Unix millisecond timestamp of its last authenticated activity.
type Traffic struct {
	Up       uint64 `json:"up"`
	Down     uint64 `json:"down"`
	LastSeen int64  `json:"last_seen"`
}

func (s *Store) LoadTraffic() (map[string]Traffic, error) {
	out := make(map[string]Traffic)
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketTraffic)
		if b == nil {
			return nil
		}
		return b.ForEach(func(id, v []byte) error {
			if len(v) != 24 {
				return fmt.Errorf("invalid traffic record for %q", id)
			}
			out[string(id)] = Traffic{binary.BigEndian.Uint64(v), binary.BigEndian.Uint64(v[8:]), int64(binary.BigEndian.Uint64(v[16:]))}
			return nil
		})
	})
	return out, err
}

func (s *Store) SaveTraffic(updates map[string]Traffic) error {
	if len(updates) == 0 {
		return nil
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists(bucketTraffic)
		if err != nil {
			return err
		}
		// bbolt keeps each value until the transaction commits.
		for id, v := range updates {
			var raw [24]byte
			binary.BigEndian.PutUint64(raw[:], v.Up)
			binary.BigEndian.PutUint64(raw[8:], v.Down)
			binary.BigEndian.PutUint64(raw[16:], uint64(v.LastSeen))
			if err := b.Put([]byte(id), raw[:]); err != nil {
				return err
			}
		}
		return nil
	})
}
