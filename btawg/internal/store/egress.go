package store

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	bolt "go.etcd.io/bbolt"
)

const maxEgressRoutes = 128

var (
	bucketEgressRoles        = []byte("egress_roles")
	bucketEgressRoutes       = []byte("egress_routes")
	bucketEgressRetired      = []byte("egress_retired")
	bucketEgressRevision     = []byte("egress_revision")
	bucketEgressClientEpochs = []byte("egress_client_epochs")
	bucketEgressGroupEpochs  = []byte("egress_group_epochs")

	// ErrInvalidEgressRoute reports a route that cannot be saved.
	ErrInvalidEgressRoute = errors.New("invalid egress route")
	// ErrEgressRouteUnavailable reports a denied or no longer usable route.
	ErrEgressRouteUnavailable = errors.New("egress route unavailable")
	// ErrEgressRouteNotFound reports an unknown route in the admin catalogue.
	ErrEgressRouteNotFound = errors.New("egress route not found")
	// ErrEgressConflict reports that a form predates a catalogue mutation.
	ErrEgressConflict = errors.New("route settings changed; reload the page and try again")
)

// EgressRole holds the hub's authorization for a device to serve routes.
type EgressRole struct {
	Exit    bool `json:"exit"`
	Transit bool `json:"transit"`
}

// EgressRoute names an exit or a transit followed by an exit. Clients and
// Groups are explicit lists of allowed origin IDs; their union grants access.
type EgressRoute struct {
	ID            string   `json:"id"`
	Name          string   `json:"name"`
	Hops          []string `json:"hops"`
	Clients       []string `json:"clients"`
	Groups        []string `json:"groups"`
	Authorization uint64   `json:"-"`
}

// EgressRevision returns the catalogue version for optimistic admin updates.
// Read it before loading form data so a concurrent change invalidates the form.
func (s *Store) EgressRevision() (uint64, error) {
	var revision uint64
	err := s.db.View(func(tx *bolt.Tx) error {
		revision = egressRevision(tx)
		return nil
	})
	return revision, err
}

func egressRevision(tx *bolt.Tx) uint64 {
	if b := tx.Bucket(bucketEgressRevision); b != nil {
		return b.Sequence()
	}
	return 0
}

func advanceEgressRevision(tx *bolt.Tx) (uint64, error) {
	b, err := tx.CreateBucketIfNotExists(bucketEgressRevision)
	if err != nil {
		return 0, err
	}
	return b.NextSequence()
}

func (s *Store) updateEgress(expected *uint64, update func(*bolt.Tx) error) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		if expected != nil && *expected != egressRevision(tx) {
			return ErrEgressConflict
		}
		if err := update(tx); err != nil {
			return err
		}
		_, err := advanceEgressRevision(tx)
		return err
	})
}

// Called in the store deletion or replacement transaction, so an exact ID
// reuse cannot retain access and pending admin forms cannot bind a new device.
func invalidateEgressClientTx(tx *bolt.Tx, id string) error {
	if b := tx.Bucket(bucketEgressRoles); b != nil {
		if err := b.Delete([]byte(id)); err != nil {
			return err
		}
	}
	return invalidateEgressIdentity(tx, bucketEgressClientEpochs, id)
}

func invalidateEgressGroupTx(tx *bolt.Tx, id string) error {
	return invalidateEgressIdentity(tx, bucketEgressGroupEpochs, id)
}

func invalidateEgressIdentity(tx *bolt.Tx, bucket []byte, id string) error {
	revision, err := advanceEgressRevision(tx)
	if err != nil {
		return err
	}
	b, err := tx.CreateBucketIfNotExists(bucket)
	if err != nil {
		return err
	}
	var raw [8]byte
	binary.BigEndian.PutUint64(raw[:], revision)
	return b.Put([]byte(id), raw[:])
}

func egressEpoch(tx *bolt.Tx, bucket []byte, id string) uint64 {
	if b := tx.Bucket(bucket); b != nil {
		if raw := b.Get([]byte(id)); raw != nil {
			return binary.BigEndian.Uint64(raw)
		}
	}
	return 0
}

// Pin the enrolled device, not its VPN address. Moving groups or renumbering
// does not change the identity; ID reuse with new credentials is not a grant.
type egressIdentity struct {
	PubKey  string    `json:"pub_key"`
	PeerID  string    `json:"peer_id"`
	Created time.Time `json:"created"`
	Epoch   uint64    `json:"epoch"`
}

func egressIdentityOf(tx *bolt.Tx, c ClientRecord) egressIdentity {
	return egressIdentity{PubKey: c.PubKey, PeerID: c.PeerID, Created: c.Created, Epoch: egressEpoch(tx, bucketEgressClientEpochs, c.ID)}
}

func (i egressIdentity) matches(c egressIdentity) bool {
	return i.PubKey == c.PubKey && i.PeerID == c.PeerID && i.Created.Equal(c.Created) && i.Epoch == c.Epoch
}

// IDs are stored in the public route; these pins follow the same slice order.
type storedEgressRoute struct {
	EgressRoute
	HopIdentities    []egressIdentity `json:"hop_identities"`
	ClientIdentities []egressIdentity `json:"client_identities"`
	GroupEpochs      []uint64         `json:"group_epochs"`
	PolicyRevision   uint64           `json:"policy_revision"`
}

type storedEgressRole struct {
	EgressRole
	Device       egressIdentity `json:"device"`
	RoleRevision uint64         `json:"role_revision"`
}

// SetEgressRole grants or removes roles for the current active device.
func (s *Store) SetEgressRole(clientID string, role EgressRole) error {
	return s.setEgressRole(clientID, role, nil)
}

// SetEgressRoleAtRevision applies a role form only to the catalogue it read.
func (s *Store) SetEgressRoleAtRevision(clientID string, role EgressRole, revision uint64) error {
	return s.setEgressRole(clientID, role, &revision)
}

func (s *Store) setEgressRole(clientID string, role EgressRole, expected *uint64) error {
	return s.updateEgress(expected, func(tx *bolt.Tx) error {
		client, err := egressClient(tx, clientID)
		if err != nil {
			return err
		}
		if client.Revoked {
			return fmt.Errorf("device %q is revoked: %w", clientID, ErrEgressRouteUnavailable)
		}
		key := []byte(clientID)
		if role == (EgressRole{}) {
			if b := tx.Bucket(bucketEgressRoles); b != nil {
				return b.Delete(key)
			}
			return nil
		}
		b, err := tx.CreateBucketIfNotExists(bucketEgressRoles)
		if err != nil {
			return err
		}
		next := storedEgressRole{EgressRole: role, Device: egressIdentityOf(tx, client), RoleRevision: egressRevision(tx) + 1}
		var old storedEgressRole
		if raw := b.Get(key); raw != nil && json.Unmarshal(raw, &old) == nil && old.Device.matches(next.Device) && old.EgressRole == role {
			next.RoleRevision = old.RoleRevision
		}
		return b.Put(key, mustJSON(next))
	})
}

// EgressRole returns the current device's active grants. Revoked devices have
// no grants, and a missing client ID returns ErrNotFound.
func (s *Store) EgressRole(clientID string) (EgressRole, error) {
	var role EgressRole
	err := s.db.View(func(tx *bolt.Tx) error {
		client, err := egressClient(tx, clientID)
		if err != nil {
			return err
		}
		role, err = egressRole(tx, client)
		return err
	})
	return role, err
}

func egressClient(tx *bolt.Tx, id string) (ClientRecord, error) {
	var client ClientRecord
	raw := tx.Bucket(bucketClients).Get([]byte(id))
	if raw == nil {
		return client, ErrNotFound
	}
	if err := json.Unmarshal(raw, &client); err != nil {
		return ClientRecord{}, err
	}
	NormalizeClientRecord(&client)
	return client, nil
}

func egressRole(tx *bolt.Tx, client ClientRecord) (EgressRole, error) {
	r, err := loadEgressRole(tx, client)
	return r.EgressRole, err
}

func loadEgressRole(tx *bolt.Tx, client ClientRecord) (storedEgressRole, error) {
	b := tx.Bucket(bucketEgressRoles)
	if client.Revoked || b == nil {
		return storedEgressRole{}, nil
	}
	raw := b.Get([]byte(client.ID))
	if raw == nil {
		return storedEgressRole{}, nil
	}
	var role storedEgressRole
	if err := json.Unmarshal(raw, &role); err != nil {
		return storedEgressRole{}, err
	}
	if !role.Device.matches(egressIdentityOf(tx, client)) {
		return storedEgressRole{}, nil
	}
	return role, nil
}

func sameEgressDevice(a, b ClientRecord) bool {
	return a.ID == b.ID || (a.PubKey != "" && strings.EqualFold(a.PubKey, b.PubKey)) ||
		(a.PeerID != "" && a.PeerID == b.PeerID) || (a.IP != "" && a.IP == b.IP)
}

// SaveEgressRoute creates or replaces a route by ID, validating references and
// capturing the devices that the administrator selected in the write transaction.
func (s *Store) SaveEgressRoute(route EgressRoute) error {
	return s.saveEgressRoute(route, nil, false)
}

// CreateEgressRouteAtRevision creates a fresh ID only if the form is current.
func (s *Store) CreateEgressRouteAtRevision(route EgressRoute, revision uint64) error {
	return s.saveEgressRoute(route, &revision, true)
}

// SaveEgressRouteAtRevision edits an existing route only if the form is current.
func (s *Store) SaveEgressRouteAtRevision(route EgressRoute, revision uint64) error {
	return s.saveEgressRoute(route, &revision, false)
}

func (s *Store) saveEgressRoute(route EgressRoute, expected *uint64, create bool) error {
	route.Name = strings.TrimSpace(route.Name)
	if route.ID == "" || route.ID == "hub" || !utf8.ValidString(route.ID) || strings.IndexFunc(route.ID, func(r rune) bool {
		return unicode.IsSpace(r) || unicode.IsControl(r)
	}) >= 0 {
		return fmt.Errorf("%w: invalid or reserved route ID", ErrInvalidEgressRoute)
	}
	if route.Name == "" || len(route.Name) > 128 || !utf8.ValidString(route.Name) || strings.IndexFunc(route.Name, unicode.IsControl) >= 0 {
		return fmt.Errorf("%w: route name must be printable and 1–128 bytes", ErrInvalidEgressRoute)
	}
	if len(route.Hops) < 1 || len(route.Hops) > 2 {
		return fmt.Errorf("%w: choose one exit and optionally one transit before it", ErrInvalidEgressRoute)
	}
	return s.updateEgress(expected, func(tx *bolt.Tx) error {
		key := []byte(route.ID)
		if retired := tx.Bucket(bucketEgressRetired); retired != nil && retired.Get(key) != nil {
			return fmt.Errorf("%w: route ID has been retired", ErrInvalidEgressRoute)
		}
		b, err := tx.CreateBucketIfNotExists(bucketEgressRoutes)
		if err != nil {
			return err
		}
		var prior storedEgressRoute
		if raw := b.Get(key); raw != nil {
			if create {
				return fmt.Errorf("%w: route ID already exists", ErrInvalidEgressRoute)
			}
			if err := json.Unmarshal(raw, &prior); err != nil {
				return err
			}
			if len(prior.Hops) != len(prior.HopIdentities) || len(prior.Clients) != len(prior.ClientIdentities) {
				return fmt.Errorf("invalid stored egress device identity pins for %q", route.ID)
			}
		} else {
			if expected != nil && !create {
				return ErrEgressRouteNotFound
			}
			cursor := b.Cursor()
			count := 0
			for k, _ := cursor.First(); k != nil; k, _ = cursor.Next() {
				count++
				if count == maxEgressRoutes {
					return fmt.Errorf("%w: cannot exceed %d named routes", ErrInvalidEgressRoute, maxEgressRoutes)
				}
			}
		}
		// A rename or ACL edit must never transfer an existing grant to a
		// replacement device, even when the retained ID changes hop position.
		priorDevices := make(map[string]egressIdentity, len(prior.Hops)+len(prior.Clients))
		for i, id := range prior.Hops {
			priorDevices[id] = prior.HopIdentities[i]
		}
		for i, id := range prior.Clients {
			priorDevices[id] = prior.ClientIdentities[i]
		}
		rec := storedEgressRoute{
			EgressRoute:      route,
			HopIdentities:    make([]egressIdentity, len(route.Hops)),
			ClientIdentities: make([]egressIdentity, len(route.Clients)),
			GroupEpochs:      make([]uint64, len(route.Groups)),
		}
		var hops [2]ClientRecord
		for i, id := range route.Hops {
			client, err := egressClient(tx, id)
			if err == ErrNotFound || (err == nil && client.Revoked) {
				return fmt.Errorf("%w: hop %q is missing or revoked", ErrInvalidEgressRoute, id)
			}
			if err != nil {
				return err
			}
			if i > 0 && sameEgressDevice(hops[0], client) {
				return fmt.Errorf("%w: cannot use the same device twice", ErrInvalidEgressRoute)
			}
			role, err := egressRole(tx, client)
			if err != nil {
				return err
			}
			if i == len(route.Hops)-1 {
				if !role.Exit {
					return fmt.Errorf("%w: device %q does not have the exit role", ErrInvalidEgressRoute, id)
				}
			} else if !role.Transit {
				return fmt.Errorf("%w: device %q does not have the transit role", ErrInvalidEgressRoute, id)
			}
			hops[i] = client
			rec.HopIdentities[i] = egressIdentityOf(tx, client)
			if old, ok := priorDevices[id]; ok && !old.matches(rec.HopIdentities[i]) {
				return fmt.Errorf("%w: hop %q was replaced; save a route without it before adding it back", ErrInvalidEgressRoute, id)
			}
		}
		for i, id := range route.Clients {
			client, err := egressClient(tx, id)
			if err == ErrNotFound || (err == nil && client.Revoked) {
				return fmt.Errorf("%w: audience device %q is missing or revoked", ErrInvalidEgressRoute, id)
			}
			if err != nil {
				return err
			}
			for _, hop := range hops[:len(route.Hops)] {
				if sameEgressDevice(client, hop) {
					return fmt.Errorf("%w: device %q cannot use its own route", ErrInvalidEgressRoute, id)
				}
			}
			rec.ClientIdentities[i] = egressIdentityOf(tx, client)
			if old, ok := priorDevices[id]; ok && !old.matches(rec.ClientIdentities[i]) {
				return fmt.Errorf("%w: audience device %q was replaced; save without it before adding it back", ErrInvalidEgressRoute, id)
			}
		}
		groups := tx.Bucket(bucketGroups)
		for i, id := range route.Groups {
			if groups.Get([]byte(id)) == nil {
				return fmt.Errorf("%w: unknown audience group %q", ErrInvalidEgressRoute, id)
			}
			epoch := egressEpoch(tx, bucketEgressGroupEpochs, id)
			if j := slices.Index(prior.Groups, id); j >= 0 && (j >= len(prior.GroupEpochs) || prior.GroupEpochs[j] != epoch) {
				return fmt.Errorf("%w: audience group %q was replaced; save without it before adding it back", ErrInvalidEgressRoute, id)
			}
			rec.GroupEpochs[i] = epoch
		}
		rec.PolicyRevision = prior.PolicyRevision
		if prior.ID == "" || !slices.Equal(prior.Hops, rec.Hops) || !slices.Equal(prior.Clients, rec.Clients) || !slices.Equal(prior.Groups, rec.Groups) {
			rec.PolicyRevision = egressRevision(tx) + 1
		}
		return b.Put(key, mustJSON(rec))
	})
}

// DeleteEgressRoute removes an administrative record, even if it has become invalid.
func (s *Store) DeleteEgressRoute(id string) error {
	return s.deleteEgressRoute(id, nil)
}

// DeleteEgressRouteAtRevision deletes a route only if the form is current.
func (s *Store) DeleteEgressRouteAtRevision(id string, revision uint64) error {
	return s.deleteEgressRoute(id, &revision)
}

func (s *Store) deleteEgressRoute(id string, expected *uint64) error {
	return s.updateEgress(expected, func(tx *bolt.Tx) error {
		b, key := tx.Bucket(bucketEgressRoutes), []byte(id)
		if b == nil || b.Get(key) == nil {
			return ErrEgressRouteNotFound
		}
		retired, err := tx.CreateBucketIfNotExists(bucketEgressRetired)
		if err != nil {
			return err
		}
		if err := retired.Put(key, []byte{1}); err != nil {
			return err
		}
		return b.Delete(key)
	})
}

// ListEgressRoutes returns all saved records, including invalid routes, in ID order.
func (s *Store) ListEgressRoutes() ([]EgressRoute, error) {
	var routes []EgressRoute
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketEgressRoutes)
		if b == nil {
			return nil
		}
		return b.ForEach(func(_, v []byte) error {
			var r EgressRoute
			if err := json.Unmarshal(v, &r); err != nil {
				return err
			}
			routes = append(routes, r)
			return nil
		})
	})
	return routes, err
}

// AuthorizedEgressRoutes returns the named routes available to an active
// client in ID order. The hub's separate Internet ACL is not a route grant.
func (s *Store) AuthorizedEgressRoutes(clientID string) ([]EgressRoute, error) {
	var routes []EgressRoute
	err := s.db.View(func(tx *bolt.Tx) error {
		origin, err := egressClient(tx, clientID)
		if err == ErrNotFound || (err == nil && origin.Revoked) {
			return nil
		}
		if err != nil {
			return err
		}
		b := tx.Bucket(bucketEgressRoutes)
		if b == nil {
			return nil
		}
		var hops [2]ClientRecord
		return b.ForEach(func(_, v []byte) error {
			var r storedEgressRoute
			if err := json.Unmarshal(v, &r); err != nil {
				return err
			}
			if err := resolveEgressHops(tx, origin, &r, &hops); err != nil {
				if err == ErrEgressRouteUnavailable {
					return nil
				}
				return err
			}
			routes = append(routes, r.EgressRoute)
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	return routes, nil
}

// ResolveEgressRoute authorizes a single route and returns its current hop
// records in path order. Origin, ACL, roles and devices share one DB snapshot.
func (s *Store) ResolveEgressRoute(clientID, routeID string) (EgressRoute, []ClientRecord, error) {
	var r storedEgressRoute
	var hops [2]ClientRecord
	err := s.db.View(func(tx *bolt.Tx) error {
		origin, err := egressClient(tx, clientID)
		if err == ErrNotFound || (err == nil && origin.Revoked) {
			return ErrEgressRouteUnavailable
		}
		if err != nil {
			return err
		}
		b := tx.Bucket(bucketEgressRoutes)
		if b == nil || routeID == "hub" {
			return ErrEgressRouteUnavailable
		}
		raw := b.Get([]byte(routeID))
		if raw == nil {
			return ErrEgressRouteUnavailable
		}
		if err := json.Unmarshal(raw, &r); err != nil {
			return err
		}
		return resolveEgressHops(tx, origin, &r, &hops)
	})
	if err != nil {
		return EgressRoute{}, nil, err
	}
	return r.EgressRoute, hops[:len(r.Hops)], nil
}

func resolveEgressHops(tx *bolt.Tx, origin ClientRecord, route *storedEgressRoute, hops *[2]ClientRecord) error {
	if len(route.Hops) == 0 || len(route.Hops) > len(hops) || len(route.HopIdentities) != len(route.Hops) ||
		len(route.ClientIdentities) != len(route.Clients) || slices.Contains(route.Hops, origin.ID) {
		return ErrEgressRouteUnavailable
	}
	groupIndex := slices.Index(route.Groups, origin.GroupID)
	allowed := groupIndex >= 0 && groupIndex < len(route.GroupEpochs) &&
		tx.Bucket(bucketGroups).Get([]byte(origin.GroupID)) != nil &&
		route.GroupEpochs[groupIndex] == egressEpoch(tx, bucketEgressGroupEpochs, origin.GroupID)
	if !allowed {
		for i, id := range route.Clients {
			if id == origin.ID && route.ClientIdentities[i].matches(egressIdentityOf(tx, origin)) {
				allowed = true
				break
			}
		}
	}
	if !allowed {
		return ErrEgressRouteUnavailable
	}
	route.Authorization = max(route.PolicyRevision, egressEpoch(tx, bucketEgressClientEpochs, origin.ID))
	for i, id := range route.Hops {
		client, err := egressClient(tx, id)
		if err == ErrNotFound {
			return ErrEgressRouteUnavailable
		}
		if err != nil {
			return err
		}
		if client.Revoked || !route.HopIdentities[i].matches(egressIdentityOf(tx, client)) || sameEgressDevice(origin, client) ||
			(i > 0 && sameEgressDevice(hops[0], client)) {
			return ErrEgressRouteUnavailable
		}
		role, err := loadEgressRole(tx, client)
		if err != nil {
			return err
		}
		if (i == len(route.Hops)-1 && !role.Exit) || (i < len(route.Hops)-1 && !role.Transit) {
			return ErrEgressRouteUnavailable
		}
		hops[i] = client
		route.Authorization = max(route.Authorization, role.RoleRevision)
	}
	return nil
}
