// Package store persists the btawg hub state in an embedded bbolt database:
// the server configuration (bucket `server`, single key) and one record per
// client (bucket `clients`, key = client ID). All values are JSON.
package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	bolt "go.etcd.io/bbolt"

	"bittorrent-tunnel/btawg/internal/config"
)

var (
	bucketServer  = []byte("server")
	bucketClients = []byte("clients")
	serverKey     = []byte("config")
)

// ErrNotFound is returned by GetClient for an unknown ID.
var ErrNotFound = errors.New("client not found")

// ErrDuplicateIP and ErrDuplicatePeerID are returned by CreateClient when the
// new record collides with an existing client.
var (
	ErrDuplicateIP     = errors.New("client IP already in use")
	ErrDuplicatePeerID = errors.New("client peer ID already in use")
)

// ClientRecord is one deployed client: its AWG key pair, overlay address and
// the BitTorrent peer ID the server uses to recognize its carrier handshake.
type ClientRecord struct {
	ID      string    `json:"id"`
	Name    string    `json:"name"`
	PubKey  string    `json:"pubkey"`
	PrivKey string    `json:"privkey"` // secret
	IP      string    `json:"ip"`
	PeerID  string    `json:"peer_id"`
	Created time.Time `json:"created"`
	Revoked bool      `json:"revoked"`
}

// Store wraps the bbolt database.
type Store struct {
	db *bolt.DB
}

// Open creates or opens the database at path.
func Open(path string) (*Store, error) {
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("open store: %w", err)
	}
	err = db.Update(func(tx *bolt.Tx) error {
		for _, b := range [][]byte{bucketServer, bucketClients} {
			if _, e := tx.CreateBucketIfNotExists(b); e != nil {
				return e
			}
		}
		return nil
	})
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("init buckets: %w", err)
	}
	return &Store{db: db}, nil
}

// Close releases the database.
func (s *Store) Close() error { return s.db.Close() }

// SaveServerConfig persists the hub configuration.
func (s *Store) SaveServerConfig(cfg config.ServerConfig) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b, err := json.Marshal(cfg)
		if err != nil {
			return err
		}
		return tx.Bucket(bucketServer).Put(serverKey, b)
	})
}

// LoadServerConfig returns the saved hub configuration, or the shipped
// defaults when nothing has been saved yet.
func (s *Store) LoadServerConfig() (config.ServerConfig, error) {
	var cfg config.ServerConfig
	err := s.db.View(func(tx *bolt.Tx) error {
		raw := tx.Bucket(bucketServer).Get(serverKey)
		if raw == nil {
			cfg = config.DefaultServerConfig()
			return nil
		}
		return json.Unmarshal(raw, &cfg)
	})
	return cfg, err
}

// CreateClient stores a new client record. It rejects records whose IP or
// peer ID collides with any existing client (revoked or not).
func (s *Store) CreateClient(rec ClientRecord) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketClients)
		var dupErr error
		b.ForEach(func(_, v []byte) error {
			var existing ClientRecord
			if json.Unmarshal(v, &existing) != nil {
				return nil
			}
			switch {
			case existing.IP == rec.IP:
				dupErr = ErrDuplicateIP
			case existing.PeerID == rec.PeerID:
				dupErr = ErrDuplicatePeerID
			}
			return nil
		})
		if dupErr != nil {
			return dupErr
		}
		return b.Put([]byte(rec.ID), mustJSON(rec))
	})
}

// ListClients returns all client records in insertion order.
func (s *Store) ListClients() ([]ClientRecord, error) {
	var recs []ClientRecord
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketClients).ForEach(func(_, v []byte) error {
			var rec ClientRecord
			if err := json.Unmarshal(v, &rec); err != nil {
				return err
			}
			recs = append(recs, rec)
			return nil
		})
	})
	return recs, err
}

// GetClient returns one client record by ID.
func (s *Store) GetClient(id string) (ClientRecord, error) {
	var rec ClientRecord
	err := s.db.View(func(tx *bolt.Tx) error {
		raw := tx.Bucket(bucketClients).Get([]byte(id))
		if raw == nil {
			return ErrNotFound
		}
		return json.Unmarshal(raw, &rec)
	})
	return rec, err
}

// RevokeClient marks a client revoked; its carrier is torn down by the caller.
func (s *Store) RevokeClient(id string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketClients)
		raw := b.Get([]byte(id))
		if raw == nil {
			return ErrNotFound
		}
		var rec ClientRecord
		if err := json.Unmarshal(raw, &rec); err != nil {
			return err
		}
		rec.Revoked = true
		return b.Put([]byte(id), mustJSON(rec))
	})
}

// DeleteClient removes a client record permanently.
func (s *Store) DeleteClient(id string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		if tx.Bucket(bucketClients).Get([]byte(id)) == nil {
			return ErrNotFound
		}
		return tx.Bucket(bucketClients).Delete([]byte(id))
	})
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}
