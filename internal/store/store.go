// Package store keeps the signature records in a local directory.
//
// The directory is the only state the service has, and it is meant to be a
// mounted volume that is backed up:
//
//	config.json              settings maintainers change (allowlist, CLA revision, branding)
//	logo.svg or logo.png     optional logo for the page header
//	grandfathered.json       account IDs treated as having signed
//	signatures/<id>.json     one signed record per account
//	pending/<id>.json        employer signatures waiting for an admin
//	audit/events.jsonl       the hash-chained log of every change, see package audit
//
// A check needs file names only, so lookups never read record contents.
// Every change to a record is followed by an audit event naming the digest
// of the new file. Edits made by hand to config.json or grandfathered.json
// are picked up on the next refresh and logged as well.
package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/rotki/cla/internal/audit"
	"github.com/rotki/cla/internal/site"
)

const (
	SignedDir  = "signatures"
	PendingDir = "pending"
	ConfigFile = "config.json"
	// LogoFiles are looked for in this order; the first one found is the
	// logo shown in the page header.
	LogoSVG       = "logo.svg"
	LogoPNG       = "logo.png"
	Grandfathered = "grandfathered.json"
	AuditLog      = "audit/events.jsonl"
)

// ErrExists is returned when creating a record that is already there.
var ErrExists = errors.New("record already exists")

// ErrNotFound is returned for a missing record.
var ErrNotFound = errors.New("record not found")

// ErrConflict is returned when confirming a pending signature for an account
// that already has a different signature on file. Nothing is changed; an
// admin resolves it by hand.
var ErrConflict = errors.New("account already has a different signature on file")

// RepoConfig is config.json. Changing it needs no redeploy: the next refresh
// picks it up and logs it.
type RepoConfig struct {
	// CLAGist is the gist ID holding the CLA text.
	CLAGist string `json:"cla_gist"`
	// CLARevision pins the gist revision shown and recorded at signing.
	CLARevision string `json:"cla_revision"`
	// Allowlist holds logins that never need to sign.
	Allowlist []string `json:"allowlist"`
	// ExemptTeam is the slug of the org team whose members are exempt.
	ExemptTeam string `json:"exempt_team"`
	// ExcludedRepos are never checked.
	ExcludedRepos []string `json:"excluded_repos"`
	// Site is the branding shown on the pages.
	Site site.Settings `json:"site"`
}

// Record is one signature file.
type Record struct {
	GitHubID    int64     `json:"github_id"`
	Login       string    `json:"login"`
	SignedAt    time.Time `json:"signed_at"`
	CLARevision string    `json:"cla_revision"`
	Category    string    `json:"category"`
	Company     string    `json:"company,omitempty"`
	Role        string    `json:"role,omitempty"`
	PR          string    `json:"pr,omitempty"`
	Origin      string    `json:"origin"`
	KeyID       string    `json:"key_id"`
	ConfirmedBy string    `json:"confirmed_by,omitempty"`
	ConfirmedAt time.Time `json:"confirmed_at,omitzero"`
	PII         string    `json:"pii"`
	// Salt keys the account's pseudonym in the audit log. It lives only
	// here, so deleting the record unlinks the account's events.
	Salt string `json:"salt"`
}

// Subject is the record's pseudonym in the audit log.
func (r Record) Subject() string {
	return audit.Subject(r.Salt, r.GitHubID)
}

const (
	Individual = "individual"
	Employer   = "employer"
)

// Standing is where a GitHub account stands with the CLA.
type Standing int

const (
	NotSigned Standing = iota
	Pending
	Signed
	GrandfatheredIn
)

type snapshot struct {
	signed        map[int64]bool
	pending       map[int64]bool
	grandfathered map[int64]bool
	config        RepoConfig
	configDigest  string
	logo          logo
	grandDigest   string
	head          string
}

type Store struct {
	dir string
	now func() time.Time

	mu   sync.RWMutex
	snap *snapshot

	// writeMu orders writers inside the process; audit.Lock orders them
	// against cla-tool.
	writeMu sync.Mutex
	// chain is how far the audit log was verified, so each write checks
	// only what was appended since. Guarded by writeMu.
	chain audit.Chain
	// wait is lockWait, shorter in tests.
	wait time.Duration
	// The logo last read, the name, size and time it was read at, and the
	// last problem warned about. Guarded by writeMu.
	logoCached  logo
	logoKey     string
	logoProblem string
}

// lockWait bounds how long a write waits for both locks together, so a
// request gets an error well inside the server's 60 s write timeout.
const lockWait = 20 * time.Second

// lock takes writeMu and then the directory lock within one lockWait.
func (s *Store) lock() (func(), error) {
	deadline := time.Now().Add(s.wait)
	for !s.writeMu.TryLock() {
		if time.Now().After(deadline) {
			return nil, audit.ErrLockTimeout
		}
		time.Sleep(10 * time.Millisecond)
	}
	unlock, err := audit.LockUntil(s.dir, deadline)
	if err != nil {
		s.writeMu.Unlock()
		return nil, err
	}
	return func() {
		unlock()
		s.writeMu.Unlock()
	}, nil
}

// New returns a store on dir. Nothing is read until the first Refresh.
func New(dir string) *Store {
	return &Store{dir: dir, now: time.Now, wait: lockWait}
}

// Dir is the data directory.
func (s *Store) Dir() string {
	return s.dir
}

func (s *Store) path(rel string) string {
	return filepath.Join(s.dir, filepath.FromSlash(rel))
}

// Ready reports whether a snapshot has been loaded.
func (s *Store) Ready() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.snap != nil
}

// Refresh reloads the snapshot from the directory: two directory listings
// and two small files. A changed config.json or grandfathered.json is logged.
func (s *Store) Refresh(_ context.Context) error {
	unlock, err := s.lock()
	if err != nil {
		return err
	}
	defer unlock()
	return s.refreshLocked()
}

// refreshLocked is Refresh for a caller holding both locks.
func (s *Store) refreshLocked() error {
	next := &snapshot{grandfathered: map[int64]bool{}}
	var err error
	if next.signed, err = s.listIDs(SignedDir); err != nil {
		return err
	}
	if next.pending, err = s.listIDs(PendingDir); err != nil {
		return err
	}

	data, err := readOptional(s.path(ConfigFile))
	if err != nil {
		return err
	}
	if data != nil {
		if err := json.Unmarshal(data, &next.config); err != nil {
			return fmt.Errorf("parsing %s: %w", ConfigFile, err)
		}
		next.configDigest = audit.Digest(data)
	}
	data, err = readOptional(s.path(Grandfathered))
	if err != nil {
		return err
	}
	if data != nil {
		var ids []int64
		if err := json.Unmarshal(data, &ids); err != nil {
			return fmt.Errorf("parsing %s: %w", Grandfathered, err)
		}
		for _, id := range ids {
			next.grandfathered[id] = true
		}
		next.grandDigest = audit.Digest(data)
	}

	next.logo = s.readLogo()

	s.mu.RLock()
	old := s.snap
	s.mu.RUnlock()
	if old == nil || old.configDigest != next.configDigest || old.grandDigest != next.grandDigest {
		// The same pass checks the chain, so the next write only has to
		// check what was appended after it.
		chain, err := logFileChanges(s.dir, "service", s.now())
		if err != nil {
			s.chain = audit.Chain{}
			return err
		}
		s.chain = chain
	}
	last, _, err := audit.Last(s.path(AuditLog))
	if err != nil {
		return err
	}
	next.head = last.Hash

	s.mu.Lock()
	s.snap = next
	s.mu.Unlock()
	return nil
}

// logo is the optional header logo.
type logo struct {
	data        []byte
	contentType string
	version     string
}

// maxLogo bounds the logo file; a header logo is a few kilobytes.
const maxLogo = 256 << 10

// readLogo loads logo.svg or logo.png, if there is one. A file that is not
// a regular file, or too large, is skipped with one warning: the pages then
// show the letter mark, as without a logo. A file whose name, size and
// modification time are those of the logo already loaded is not read again.
// The caller holds writeMu.
func (s *Store) readLogo() logo {
	for _, f := range []struct{ name, contentType string }{{LogoSVG, "image/svg+xml"}, {LogoPNG, "image/png"}} {
		info, err := os.Lstat(s.path(f.name))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		key := ""
		if err == nil {
			key = fmt.Sprintf("%s|%d|%d", f.name, info.Size(), info.ModTime().UnixNano())
			if key == s.logoKey {
				return s.logoCached
			}
		}
		data, err := readSmallFile(s.path(f.name), maxLogo)
		if err != nil {
			if problem := f.name + ": " + err.Error(); problem != s.logoProblem {
				slog.Warn("the logo file cannot be used, showing the letter mark", "file", f.name, "error", err)
				s.logoProblem = problem
			}
			s.logoKey, s.logoCached = "", logo{}
			return logo{}
		}
		s.logoProblem = ""
		s.logoKey = key
		s.logoCached = logo{data: data, contentType: f.contentType, version: audit.Digest(data)[:16]}
		return s.logoCached
	}
	s.logoKey, s.logoCached, s.logoProblem = "", logo{}, ""
	return logo{}
}

// readSmallFile reads a regular file of at most limit bytes, without
// following a symlink. It opens without blocking, so a FIFO put in the
// file's place is refused instead of waiting forever for a writer.
func readSmallFile(path string, limit int64) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("not a regular file")
	}
	if info.Size() > limit {
		return nil, fmt.Errorf("larger than %d bytes", limit)
	}
	data := make([]byte, info.Size())
	_, err = io.ReadFull(f, data)
	return data, err
}

// Logo returns the header logo, its content type and a version that
// changes with its contents; data is nil when there is none.
func (s *Store) Logo() (data []byte, contentType, version string) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.snap == nil {
		return nil, "", ""
	}
	return s.snap.logo.data, s.snap.logo.contentType, s.snap.logo.version
}

// LogFileChanges appends an event for config.json and grandfathered.json
// when either differs from what the log last recorded for it. The caller
// holds audit.Lock.
func LogFileChanges(dir, actor string, now time.Time) error {
	_, err := logFileChanges(dir, actor, now)
	return err
}

// logFileChanges is LogFileChanges, returning how far it checked the chain
// (before anything it appended).
func logFileChanges(dir, actor string, now time.Time) (audit.Chain, error) {
	logPath := filepath.Join(dir, filepath.FromSlash(AuditLog))
	recorded := map[string]string{}
	chain, err := audit.Scan(logPath, func(e audit.Event) error {
		if e.Action == audit.Config || e.Action == audit.Grandfathered {
			recorded[e.Action] = e.Digest
		}
		return nil
	})
	if err != nil {
		return chain, fmt.Errorf("the audit log is broken, refusing to add to it: %w", err)
	}
	for action, name := range map[string]string{audit.Config: ConfigFile, audit.Grandfathered: Grandfathered} {
		data, err := readOptional(filepath.Join(dir, name))
		if err != nil {
			return chain, err
		}
		digest := ""
		if data != nil {
			digest = audit.Digest(data)
		}
		if _, ok := recorded[action]; (ok || digest != "") && recorded[action] != digest {
			if _, err := audit.Append(logPath, audit.Event{Time: now, Action: action, Actor: actor, Digest: digest}); err != nil {
				return chain, err
			}
		}
	}
	return chain, nil
}

func readOptional(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	return data, err
}

func (s *Store) listIDs(dir string) (map[int64]bool, error) {
	ids := map[int64]bool{}
	entries, err := os.ReadDir(s.path(dir))
	if errors.Is(err, os.ErrNotExist) {
		return ids, nil
	}
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		if id, ok := IDFromFile(e.Name()); ok && !e.IsDir() {
			ids[id] = true
		}
	}
	return ids, nil
}

// IDFromFile parses a record file name, <account id>.json.
func IDFromFile(file string) (int64, bool) {
	name, ok := strings.CutSuffix(file, ".json")
	if !ok {
		return 0, false
	}
	id, err := strconv.ParseInt(name, 10, 64)
	return id, err == nil && id > 0
}

// ConfigVersion changes whenever config.json does (it is the file's digest),
// so results computed under an older config are known to be stale.
func (s *Store) ConfigVersion() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.snap == nil {
		return ""
	}
	return s.snap.configDigest
}

// Head is the hash of the newest audit event when the snapshot was read.
func (s *Store) Head() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.snap == nil {
		return ""
	}
	return s.snap.head
}

// StandingOf looks up a GitHub account ID.
func (s *Store) StandingOf(id int64) Standing {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.snap == nil {
		return NotSigned
	}
	switch {
	case s.snap.signed[id]:
		return Signed
	case s.snap.grandfathered[id]:
		return GrandfatheredIn
	case s.snap.pending[id]:
		return Pending
	}
	return NotSigned
}

// Config returns config.json as of the last refresh.
func (s *Store) Config() RepoConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.snap == nil {
		return RepoConfig{}
	}
	return s.snap.config
}

// RecordPath is where an account's record lives in dir ("signatures" or
// "pending").
func RecordPath(dir string, id int64) string {
	return fmt.Sprintf("%s/%d.json", dir, id)
}

// WriteRecord writes a record durably: through a temporary file, synced and
// renamed, so a crash never leaves half a record. It returns the digest of
// what it wrote.
func WriteRecord(path string, rec Record) (string, error) {
	digest, err := WriteRecordFile(path, rec)
	if err != nil {
		return "", err
	}
	return digest, SyncDir(filepath.Dir(path))
}

// WriteRecordFile is WriteRecord without syncing the directory, for batches
// that sync each directory once at the end with SyncDir.
func WriteRecordFile(path string, rec Record) (string, error) {
	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return "", err
	}
	data = append(data, '\n')
	if err := writeFile(path, data); err != nil {
		return "", err
	}
	return audit.Digest(data), nil
}

// WriteFile writes any file of the data directory durably, the way records
// are written.
func WriteFile(path string, data []byte) error {
	if err := writeFile(path, data); err != nil {
		return err
	}
	return SyncDir(filepath.Dir(path))
}

// writeFile writes data to path through a synced temporary file and a
// rename, so a crash never leaves half a file. The directory itself is not
// synced.
func writeFile(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	// A fresh file, never an existing one: a leftover .tmp, or a symlink
	// planted in its place, is removed rather than written through.
	tmp := path + ".tmp"
	if err := os.Remove(tmp); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o640)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// RemoveRecord deletes a record file durably.
func RemoveRecord(path string) error {
	if err := os.Remove(path); err != nil {
		return err
	}
	return SyncDir(filepath.Dir(path))
}

// SyncDir makes the renames and removals in dir durable.
func SyncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	return d.Sync()
}

// ReadRecord reads and parses one record file.
func ReadRecord(path string) (Record, error) {
	var rec Record
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return rec, ErrNotFound
	}
	if err != nil {
		return rec, err
	}
	err = json.Unmarshal(data, &rec)
	return rec, err
}

// change runs fn holding both locks, then reloads the snapshot.
func (s *Store) change(fn func(logPath string) error) error {
	unlock, err := s.lock()
	if err != nil {
		return err
	}
	defer unlock()
	// Fresh state first: cla-tool may have changed records since the last
	// refresh.
	if err := s.refreshLocked(); err != nil {
		return err
	}
	// Nothing is added to a log that was tampered with. The first write
	// checks the whole chain, later ones only what was appended since; the
	// daily backup checks it all again.
	chain, err := audit.ScanFrom(s.path(AuditLog), s.chain, nil)
	if err != nil {
		s.chain = audit.Chain{}
		return fmt.Errorf("the audit log is broken, refusing to add to it: %w", err)
	}
	s.chain = chain
	if err := fn(s.path(AuditLog)); err != nil {
		return err
	}
	return s.refreshLocked()
}

// Create writes a new record into signatures/ or, for an employer signature,
// pending/. It never overwrites: an account that already has a standing
// yields ErrExists.
func (s *Store) Create(_ context.Context, rec Record) error {
	dir, action := SignedDir, audit.Signed
	if rec.Category == Employer && rec.ConfirmedBy == "" {
		dir, action = PendingDir, audit.Pending
	}
	if rec.Salt == "" {
		rec.Salt = audit.NewSalt()
	}
	return s.change(func(logPath string) error {
		if s.StandingOf(rec.GitHubID) != NotSigned {
			return ErrExists
		}
		path := s.path(RecordPath(dir, rec.GitHubID))
		digest, err := WriteRecord(path, rec)
		if err != nil {
			return err
		}
		e, err := audit.Append(logPath, audit.Event{Time: s.now(), Action: action, Subject: rec.Subject(), Actor: "signer", Digest: digest})
		if err != nil {
			// A record without its event would count as signed while the
			// signer is told it failed, and fail every verify after.
			return undoUnlessLogged(logPath, e, err, func() error { return RemoveRecord(path) })
		}
		return nil
	})
}

// undoUnlessLogged handles an append that failed: when the event is not in
// the log, it undoes the change and returns the error; when it is (the
// write landed, the sync or close failed), the change stands, since undoing
// it would leave an event no file matches, and it returns nil.
func undoUnlessLogged(logPath string, e audit.Event, appendErr error, undo func() error) error {
	if n, err := audit.Written(logPath, []audit.Event{e}); err == nil && n == 1 {
		slog.Warn("an audit event was written although its append reported an error; keeping the change", "error", appendErr)
		return nil
	}
	return errors.Join(appendErr, undo())
}

// PendingRecords returns the employer signatures waiting for an admin,
// skipping any that are already signed.
func (s *Store) PendingRecords(_ context.Context) ([]Record, error) {
	s.mu.RLock()
	var ids []int64
	if s.snap != nil {
		for id := range s.snap.pending {
			if !s.snap.signed[id] {
				ids = append(ids, id)
			}
		}
	}
	s.mu.RUnlock()
	slices.Sort(ids)

	records := make([]Record, 0, len(ids))
	for _, id := range ids {
		rec, err := ReadRecord(s.path(RecordPath(PendingDir, id)))
		if errors.Is(err, ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		records = append(records, rec)
	}
	return records, nil
}

// Confirm moves a pending employer signature into signatures/, recording the
// admin who confirmed it.
func (s *Store) Confirm(_ context.Context, id int64, admin string, now time.Time) error {
	return s.change(func(logPath string) error {
		pendingPath := s.path(RecordPath(PendingDir, id))
		rec, err := ReadRecord(pendingPath)
		if err != nil {
			return err
		}
		signedPath := s.path(RecordPath(SignedDir, id))
		var digest string
		wrote := false
		prev, err := ReadRecord(signedPath)
		switch {
		case err == nil:
			// Fine if it is this record, confirmed by an earlier attempt that
			// stopped before removing the pending file; anything else must
			// not be overwritten or dropped.
			if !prev.SignedAt.Equal(rec.SignedAt) || prev.Category != Employer || prev.Salt != rec.Salt {
				return ErrConflict
			}
			data, err := os.ReadFile(signedPath)
			if err != nil {
				return err
			}
			digest = audit.Digest(data)
		case errors.Is(err, ErrNotFound):
			rec.ConfirmedBy = admin
			rec.ConfirmedAt = now.UTC()
			// Signed and logged first, then the pending file removed: a crash
			// in between leaves the account signed and a stale pending file
			// that is ignored, and confirming again finishes the job.
			if digest, err = WriteRecord(signedPath, rec); err != nil {
				return err
			}
			wrote = true
		default:
			return err
		}
		e, err := audit.Append(logPath, audit.Event{Time: s.now(), Action: audit.Confirmed, Subject: rec.Subject(), Actor: "admin:" + admin, Digest: digest})
		if err != nil {
			err = undoUnlessLogged(logPath, e, err, func() error {
				if wrote {
					return RemoveRecord(signedPath)
				}
				return nil
			})
			if err != nil {
				return err
			}
		}
		return RemoveRecord(pendingPath)
	})
}

// Reject removes a pending employer signature.
func (s *Store) Reject(_ context.Context, id int64, admin string) error {
	return s.change(func(logPath string) error {
		pendingPath := s.path(RecordPath(PendingDir, id))
		rec, err := ReadRecord(pendingPath)
		if err != nil {
			return err
		}
		original, err := os.ReadFile(pendingPath)
		if err != nil {
			return err
		}
		if err := RemoveRecord(pendingPath); err != nil {
			return err
		}
		e, err := audit.Append(logPath, audit.Event{Time: s.now(), Action: audit.Rejected, Subject: rec.Subject(), Actor: "admin:" + admin})
		if err != nil {
			// Put the same bytes back, so the file still matches the event
			// that created it.
			return undoUnlessLogged(logPath, e, err, func() error { return WriteFile(pendingPath, original) })
		}
		return nil
	})
}
