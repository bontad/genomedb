// Package store is the node's local database. It is a real SQLite file
// (via modernc.org/sqlite, pure Go — no CGO/OpenSSL toolchain needed),
// but every sensitive column is sealed at the application layer with
// AES-256-GCM before it ever reaches a SQL statement, under a
// node-local storage key that is itself derived from the node's
// hardware-sealed root secret (crypto.LoadOrCreateRoot).
//
// This is a deliberate substitution for SQLite+SQLCipher: SQLCipher
// encrypts at the storage-engine page level and requires a CGO build
// linked against libsqlcipher/OpenSSL, which is brittle to provision on
// a machine without a system package manager. Column-level AEAD gives
// the same practical guarantee that matters here — the .db file on disk
// never contains plaintext fragment data or usable key material — while
// staying a portable, dependency-free Go binary. Swap in SQLCipher by
// changing only this file if the native dependency is acceptable in your
// deployment.
package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	_ "modernc.org/sqlite"

	mcrypto "mutant-db/crypto"
)

type Store struct {
	db         *sql.DB
	storageKey []byte // wraps fragment keys at rest; derived from this node's sealed root
}

// Open opens (creating if needed) the node's local database at path, and
// derives the local storage-wrapping key from the node's own root secret.
func Open(path string, nodeRoot []byte) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1) // modernc.org/sqlite: keep it simple, avoid locking surprises

	storageKey, err := mcrypto.DeriveFragmentRoot(nodeRoot, []byte("local-storage-wrap-key"))
	if err != nil {
		return nil, err
	}

	s := &Store{db: db, storageKey: storageKey}
	if err := s.migrate(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate() error {
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS fragments (
	pid          TEXT PRIMARY KEY,
	group_id     TEXT NOT NULL,
	group_token  TEXT NOT NULL,
	chain_id     TEXT NOT NULL,
	epoch        INTEGER NOT NULL,
	threshold    INTEGER NOT NULL,
	total        INTEGER NOT NULL,
	wrapped_key  BLOB NOT NULL,
	ciphertext   BLOB NOT NULL,
	members_json TEXT NOT NULL,
	updated_at   TIMESTAMP NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_fragments_group ON fragments(group_id);
CREATE TABLE IF NOT EXISTS manifests (
	secret_name  TEXT PRIMARY KEY,
	kind         TEXT NOT NULL DEFAULT 'secret',
	group_id     TEXT NOT NULL,
	group_token  TEXT NOT NULL,
	threshold    INTEGER NOT NULL,
	total        INTEGER NOT NULL,
	members_json TEXT NOT NULL,
	created_at   TIMESTAMP NOT NULL
);
CREATE TABLE IF NOT EXISTS mesh_peers (
	name          TEXT PRIMARY KEY,
	endpoint      TEXT NOT NULL,
	wg_public_key TEXT NOT NULL,
	added_at      TIMESTAMP NOT NULL
);
`)
	return err
}

// Member mirrors peer.Member without importing the peer package, to keep
// store dependency-free of the transport layer.
type Member struct {
	PID      string `json:"pid"`
	NodeID   string `json:"node_id"`
	Endpoint string `json:"endpoint"`
}

type Fragment struct {
	PID        string
	GroupID    string
	GroupToken string
	ChainID    string
	Epoch      uint64
	Threshold  int
	Total      int
	Key        []byte // unwrapped, in-memory only — never call this on data you're about to persist
	Ciphertext []byte
	Members    []Member
	UpdatedAt  time.Time
}

// PutFragment stores (or overwrites) a fragment this node currently
// holds. f.Key is wrapped under the node's local storage key before
// touching disk.
func (s *Store) PutFragment(f Fragment) error {
	wrapped, err := mcrypto.Encrypt(s.storageKey, f.Key, []byte("fragment-key:"+f.PID))
	if err != nil {
		return fmt.Errorf("store: wrapping fragment key: %w", err)
	}
	membersJSON, err := json.Marshal(f.Members)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`
INSERT INTO fragments (pid, group_id, group_token, chain_id, epoch, threshold, total, wrapped_key, ciphertext, members_json, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(pid) DO UPDATE SET
	group_id=excluded.group_id, group_token=excluded.group_token, chain_id=excluded.chain_id, epoch=excluded.epoch,
	threshold=excluded.threshold, total=excluded.total, wrapped_key=excluded.wrapped_key,
	ciphertext=excluded.ciphertext, members_json=excluded.members_json, updated_at=excluded.updated_at
`, f.PID, f.GroupID, f.GroupToken, f.ChainID, f.Epoch, f.Threshold, f.Total, wrapped, f.Ciphertext, string(membersJSON), time.Now())
	return err
}

var ErrNotFound = errors.New("store: not found")

const fragmentCols = `pid, group_id, group_token, chain_id, epoch, threshold, total, wrapped_key, ciphertext, members_json, updated_at`

func (s *Store) scanFragment(row *sql.Row) (Fragment, error) {
	var f Fragment
	var wrapped []byte
	var membersJSON string
	if err := row.Scan(&f.PID, &f.GroupID, &f.GroupToken, &f.ChainID, &f.Epoch, &f.Threshold, &f.Total, &wrapped, &f.Ciphertext, &membersJSON, &f.UpdatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Fragment{}, ErrNotFound
		}
		return Fragment{}, err
	}
	key, err := mcrypto.Decrypt(s.storageKey, wrapped, []byte("fragment-key:"+f.PID))
	if err != nil {
		return Fragment{}, fmt.Errorf("store: unwrapping fragment key: %w", err)
	}
	f.Key = key
	if err := json.Unmarshal([]byte(membersJSON), &f.Members); err != nil {
		return Fragment{}, err
	}
	return f, nil
}

func (s *Store) GetFragment(pid string) (Fragment, error) {
	row := s.db.QueryRow(`SELECT `+fragmentCols+` FROM fragments WHERE pid = ?`, pid)
	return s.scanFragment(row)
}

// GetFragmentByGroup finds the (at most one) fragment this node holds for
// a given group — this is what lets reconstruction and peer lookups work
// by stable group_id instead of by a pseudo-ID that may have since
// rotated.
func (s *Store) GetFragmentByGroup(groupID string) (Fragment, error) {
	row := s.db.QueryRow(`SELECT `+fragmentCols+` FROM fragments WHERE group_id = ? LIMIT 1`, groupID)
	return s.scanFragment(row)
}

// DeleteFragment removes a fragment row, used once its content has been
// re-stored under a new pseudo-ID after a mutation.
func (s *Store) DeleteFragment(pid string) error {
	_, err := s.db.Exec(`DELETE FROM fragments WHERE pid = ?`, pid)
	return err
}

// UpdateSibling rewrites one member's pid/endpoint inside every local
// fragment row that lists them — this is how a mutation notice from a
// peer (peer.MutationNoticeRequest) gets folded into local state.
func (s *Store) UpdateSibling(groupID, oldPID, newPID, newEndpoint string) error {
	rows, err := s.db.Query(`SELECT pid, members_json FROM fragments WHERE group_id = ?`, groupID)
	if err != nil {
		return err
	}
	type upd struct {
		pid, membersJSON string
	}
	var updates []upd
	for rows.Next() {
		var pid, membersJSON string
		if err := rows.Scan(&pid, &membersJSON); err != nil {
			rows.Close()
			return err
		}
		var members []Member
		if err := json.Unmarshal([]byte(membersJSON), &members); err != nil {
			rows.Close()
			return err
		}
		changed := false
		for i := range members {
			if members[i].PID == oldPID {
				members[i].PID = newPID
				members[i].Endpoint = newEndpoint
				changed = true
			}
		}
		if changed {
			b, _ := json.Marshal(members)
			updates = append(updates, upd{pid, string(b)})
		}
	}
	rows.Close()
	for _, u := range updates {
		if _, err := s.db.Exec(`UPDATE fragments SET members_json = ? WHERE pid = ?`, u.membersJSON, u.pid); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) ListFragmentPIDs() ([]string, error) {
	rows, err := s.db.Query(`SELECT pid FROM fragments`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var pids []string
	for rows.Next() {
		var pid string
		if err := rows.Scan(&pid); err != nil {
			return nil, err
		}
		pids = append(pids, pid)
	}
	return pids, nil
}

// Manifest.Kind distinguishes a regular mutation-protocol secret ("secret",
// the default — orchestrator-routed, ratchet-mutated) from an off-site
// backup ("backup" — mesh-routed, healed by periodic re-sharing instead
// of a ratchet). SelfHeal only ever touches "backup" manifests.
type Manifest struct {
	SecretName string
	Kind       string
	GroupID    string
	GroupToken string
	Threshold  int
	Total      int
	Members    []Member
	CreatedAt  time.Time
}

func (s *Store) PutManifest(m Manifest) error {
	if m.Kind == "" {
		m.Kind = "secret"
	}
	membersJSON, err := json.Marshal(m.Members)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`
INSERT INTO manifests (secret_name, kind, group_id, group_token, threshold, total, members_json, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(secret_name) DO UPDATE SET
	kind=excluded.kind, group_id=excluded.group_id, group_token=excluded.group_token, threshold=excluded.threshold,
	total=excluded.total, members_json=excluded.members_json
`, m.SecretName, m.Kind, m.GroupID, m.GroupToken, m.Threshold, m.Total, string(membersJSON), time.Now())
	return err
}

const manifestCols = `secret_name, kind, group_id, group_token, threshold, total, members_json, created_at`

func (s *Store) scanManifest(row *sql.Row) (Manifest, error) {
	var m Manifest
	var membersJSON string
	if err := row.Scan(&m.SecretName, &m.Kind, &m.GroupID, &m.GroupToken, &m.Threshold, &m.Total, &membersJSON, &m.CreatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Manifest{}, ErrNotFound
		}
		return Manifest{}, err
	}
	if err := json.Unmarshal([]byte(membersJSON), &m.Members); err != nil {
		return Manifest{}, err
	}
	return m, nil
}

func (s *Store) GetManifest(secretName string) (Manifest, error) {
	row := s.db.QueryRow(`SELECT `+manifestCols+` FROM manifests WHERE secret_name = ?`, secretName)
	return s.scanManifest(row)
}

// GetManifestByGroup looks up a manifest this node owns (if any) by
// group_id — used when a peer's mutation notice arrives carrying only the
// group_id, not the secret's human-readable name.
func (s *Store) GetManifestByGroup(groupID string) (Manifest, error) {
	row := s.db.QueryRow(`SELECT `+manifestCols+` FROM manifests WHERE group_id = ? LIMIT 1`, groupID)
	return s.scanManifest(row)
}

// ListManifestsByKind returns every manifest of a given kind this node
// owns — SelfHeal uses this to find its "backup" manifests without
// touching regular mutation-protocol secrets.
func (s *Store) ListManifestsByKind(kind string) ([]Manifest, error) {
	rows, err := s.db.Query(`SELECT `+manifestCols+` FROM manifests WHERE kind = ?`, kind)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Manifest
	for rows.Next() {
		var m Manifest
		var membersJSON string
		if err := rows.Scan(&m.SecretName, &m.Kind, &m.GroupID, &m.GroupToken, &m.Threshold, &m.Total, &membersJSON, &m.CreatedAt); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(membersJSON), &m.Members); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, nil
}

// UpdateManifestMember reflects a sibling's rotation into a manifest this
// node owns (the node that ran the original split), identified by
// group_id. It is a no-op (ErrNotFound) if this node doesn't own a
// manifest for that group — normal for the total-1 nodes that only hold a
// share, not the manifest.
func (s *Store) UpdateManifestMember(groupID, oldPID, newPID, newEndpoint string) error {
	m, err := s.GetManifestByGroup(groupID)
	if err != nil {
		return err
	}
	for i := range m.Members {
		if m.Members[i].PID == oldPID {
			m.Members[i].PID = newPID
			m.Members[i].Endpoint = newEndpoint
		}
	}
	return s.PutManifest(m)
}

// MeshPeer is one entry in this node's trusted-mesh directory — a
// family/friend device or another one of the user's own devices, reached
// over an already-established WireGuard tunnel (see package mesh). This
// list is purely local config: it never touches the orchestrator, which
// is the point — off-site backup must keep working with no central
// service involved at all.
type MeshPeer struct {
	Name        string
	Endpoint    string
	WGPublicKey string
	AddedAt     time.Time
}

func (s *Store) PutMeshPeer(p MeshPeer) error {
	_, err := s.db.Exec(`
INSERT INTO mesh_peers (name, endpoint, wg_public_key, added_at)
VALUES (?, ?, ?, ?)
ON CONFLICT(name) DO UPDATE SET endpoint=excluded.endpoint, wg_public_key=excluded.wg_public_key
`, p.Name, p.Endpoint, p.WGPublicKey, time.Now())
	return err
}

func (s *Store) DeleteMeshPeer(name string) error {
	_, err := s.db.Exec(`DELETE FROM mesh_peers WHERE name = ?`, name)
	return err
}

func (s *Store) ListMeshPeers() ([]MeshPeer, error) {
	rows, err := s.db.Query(`SELECT name, endpoint, wg_public_key, added_at FROM mesh_peers`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []MeshPeer
	for rows.Next() {
		var p MeshPeer
		if err := rows.Scan(&p.Name, &p.Endpoint, &p.WGPublicKey, &p.AddedAt); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}
