// Package records works on the data directory: it checks the records and
// their audit trail, re-encrypts them to a new key, archives them, and
// imports cla-assistant's export. It backs cla-tool and never prints personal
// data: reports name files and problems, not names or emails.
//
// Every command that changes records holds the same lock as the service and
// appends an audit event for each change, so it can run while the service
// does.
package records

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"filippo.io/age"

	"github.com/rotki/cla/internal/audit"
	"github.com/rotki/cla/internal/seal"
	"github.com/rotki/cla/internal/store"
)

// Problem is one thing wrong with one file.
type Problem struct {
	Path   string
	Reason string
}

func (p Problem) String() string {
	return p.Path + ": " + p.Reason
}

// Report sums up a Verify run.
type Report struct {
	Records       int
	ByKey         map[string]int
	Decrypted     int
	Grandfathered int
	// Events and Head describe the audit log: how many events it holds and
	// the hash of the newest, to compare with the last anchor.
	Events   int
	Head     string
	Problems []Problem
	// Notes are things worth knowing that are not wrong, such as a torn
	// write in the log. They do not make the report fail.
	Notes []Problem
}

// OK reports whether nothing is wrong.
func (r Report) OK() bool {
	return len(r.Problems) == 0
}

// file is one record file, parsed.
type file struct {
	path   string
	dir    string
	id     int64
	rec    store.Record
	digest string
}

// Verify checks every record in dir (the data directory): it parses, its
// name matches its account, the fields the service relies on are there, and,
// given identities, its personal data decrypts and is complete. It also
// checks config.json and grandfathered.json, and that the audit log is an
// unbroken chain that accounts for every file as it stands.
//
// It takes the writers' lock, so it never sees a change half made; on a
// read-only copy, such as a restored backup, it runs without.
func Verify(dir string, identities []age.Identity) (Report, error) {
	unlock, err := audit.Lock(dir)
	if errors.Is(err, audit.ErrLockTimeout) {
		return Report{}, err
	}
	if err == nil {
		defer unlock()
	}
	return verify(dir, identities)
}

func verify(dir string, identities []age.Identity) (Report, error) {
	report := Report{ByKey: map[string]int{}}
	add := func(path, reason string) {
		report.Problems = append(report.Problems, Problem{Path: path, Reason: reason})
	}

	// Verify only reads; the next write by the service or cla-tool finishes
	// the change, putting back any record its event does not cover.
	if _, err := os.Stat(filepath.Join(dir, store.JournalFile)); err == nil {
		add(store.JournalFile, "a change was interrupted; records it touched may lack their events until the next write finishes it")
	} else if !errors.Is(err, os.ErrNotExist) {
		return report, err
	}

	if err := verifyConfig(dir, add); err != nil {
		return report, err
	}
	n, err := verifyGrandfathered(dir, add)
	if err != nil {
		return report, err
	}
	report.Grandfathered = n

	files, err := readAll(dir, add, len(identities) > 0)
	if err != nil {
		return report, err
	}
	seen := map[int64]string{}
	for _, f := range files {
		report.Records++
		report.ByKey[f.rec.KeyID]++
		if other, ok := seen[f.id]; ok {
			add(f.path, "the account also has "+other)
		}
		seen[f.id] = f.path
		for _, reason := range checkRecord(f) {
			add(f.path, reason)
		}
		if len(identities) == 0 || f.rec.PII == "" {
			continue
		}
		p, err := seal.Open(f.rec.PII, identities...)
		if err != nil {
			add(f.path, fmt.Sprintf("personal data does not decrypt with the given keys (key_id %q)", f.rec.KeyID))
			continue
		}
		report.Decrypted++
		if strings.TrimSpace(p.Name) == "" && f.rec.Origin != "cla-assistant" {
			add(f.path, "the decrypted name is empty")
		}
		if !strings.Contains(p.Email, "@") && f.rec.Origin != "cla-assistant" {
			add(f.path, "the decrypted email is not an address")
		}
	}
	err = verifyAudit(dir, files, &report, add)
	return report, err
}

// lastEvent is what verify keeps of an account's newest event.
type lastEvent struct {
	Seq    int64
	Digest string
}

// verifyAudit checks the chain and that it matches the files: each record
// is what its account's last event says, no record vanished without an
// event, and the two settings files are what was last logged.
func verifyAudit(dir string, files []file, report *Report, add func(path, reason string)) error {
	// Streamed: only the newest event per account is kept, not the log.
	latest := map[string]lastEvent{}
	settings := map[string]lastEvent{}
	chain, err := audit.Scan(filepath.Join(dir, filepath.FromSlash(store.AuditLog)), func(e audit.Event) error {
		last := lastEvent{Seq: e.Seq, Digest: e.Digest}
		switch e.Action {
		case audit.Config, audit.Grandfathered:
			settings[e.Action] = last
		default:
			latest[e.Subject] = last
		}
		return nil
	})
	if err != nil {
		var pathErr *os.PathError
		if errors.As(err, &pathErr) {
			return err
		}
		add(store.AuditLog, err.Error())
	}
	report.Events, report.Head = int(chain.Events), chain.Head
	for _, line := range chain.Fragments {
		report.Notes = append(report.Notes, Problem{Path: store.AuditLog, Reason: fmt.Sprintf("line %d is a torn write, not an event; harmless, the chain continues after it", line)})
	}
	if chain.TornTail {
		report.Notes = append(report.Notes, Problem{Path: store.AuditLog, Reason: "ends in a torn write; the next event starts after it"})
	}

	present := map[string]bool{}
	for _, f := range files {
		if f.rec.Salt == "" {
			add(f.path, "salt is missing, so the audit log cannot name it")
			continue
		}
		subject := f.rec.Subject()
		present[subject] = true
		e, ok := latest[subject]
		switch {
		case !ok:
			add(f.path, "has no audit event: it was added outside the service and cla-tool")
		case e.Digest != f.digest:
			add(f.path, fmt.Sprintf("differs from its last audit event (seq %d): it was changed outside the service and cla-tool", e.Seq))
		}
	}
	for subject, e := range latest {
		if e.Digest != "" && !present[subject] {
			add(store.AuditLog, fmt.Sprintf("the record of event seq %d is gone without an audit event: it was deleted outside cla-tool", e.Seq))
		}
	}

	for action, name := range map[string]string{audit.Config: store.ConfigFile, audit.Grandfathered: store.Grandfathered} {
		data, err := os.ReadFile(filepath.Join(dir, name))
		digest := ""
		if err == nil {
			digest = audit.Digest(data)
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if e, ok := settings[action]; (ok || digest != "") && e.Digest != digest {
			add(name, "changed since its last audit event; the service logs it on its next refresh")
		}
	}
	return nil
}

// CheckAnchor reports whether event seq of the log in dir has the given
// hash, as published by an earlier anchor. A rewritten log fails it even when
// its chain is consistent.
func CheckAnchor(dir string, seq int64, hash string) error {
	events, err := audit.Read(filepath.Join(dir, filepath.FromSlash(store.AuditLog)))
	if err != nil {
		return err
	}
	if seq < 1 || seq > int64(len(events)) {
		return fmt.Errorf("the log has %d events, so no event %d: it was truncated", len(events), seq)
	}
	if got := events[seq-1].Hash; got != hash {
		return fmt.Errorf("event %d has hash %s, not the anchored %s: the log was rewritten", seq, got, hash)
	}
	return nil
}

func verifyConfig(dir string, add func(path, reason string)) error {
	path := filepath.Join(dir, store.ConfigFile)
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		add(store.ConfigFile, "missing")
		return nil
	}
	if err != nil {
		return err
	}
	var cfg store.RepoConfig
	if err := strictJSON(data, &cfg); err != nil {
		add(store.ConfigFile, "does not parse: "+err.Error())
		return nil
	}
	if cfg.CLAGist == "" || cfg.CLARevision == "" {
		add(store.ConfigFile, "cla_gist and cla_revision must be set")
	}
	return nil
}

func verifyGrandfathered(dir string, add func(path, reason string)) (int, error) {
	data, err := os.ReadFile(filepath.Join(dir, store.Grandfathered))
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	var ids []int64
	if err := json.Unmarshal(data, &ids); err != nil {
		add(store.Grandfathered, "is not a JSON array of account IDs")
		return 0, nil
	}
	for _, id := range ids {
		if id <= 0 {
			add(store.Grandfathered, fmt.Sprintf("holds an invalid account ID %d", id))
		}
	}
	return len(ids), nil
}

// checkRecord lists what is wrong with one record's plain fields.
func checkRecord(f file) []string {
	var reasons []string
	r := f.rec
	if r.GitHubID != f.id {
		reasons = append(reasons, fmt.Sprintf("github_id %d does not match the file name", r.GitHubID))
	}
	if r.SignedAt.IsZero() {
		reasons = append(reasons, "signed_at is missing")
	}
	if r.CLARevision == "" {
		reasons = append(reasons, "cla_revision is missing")
	}
	if r.Origin == "" {
		reasons = append(reasons, "origin is missing")
	}
	if r.PII == "" {
		reasons = append(reasons, "pii is missing")
	} else if !strings.HasPrefix(r.PII, "-----BEGIN AGE ENCRYPTED FILE-----") {
		reasons = append(reasons, "pii is not an armored age file, so it may be plain text")
	}
	if r.KeyID == "" {
		reasons = append(reasons, "key_id is missing")
	}
	switch r.Category {
	case store.Individual:
	case store.Employer:
		// cla-assistant's form had no employer fields, so imports lack them.
		if r.Origin != "cla-assistant" && (r.Company == "" || r.Role == "") {
			reasons = append(reasons, "an employer signature needs company and role")
		}
		if f.dir == store.SignedDir && r.ConfirmedBy == "" {
			reasons = append(reasons, "a signed employer signature needs confirmed_by")
		}
	default:
		reasons = append(reasons, fmt.Sprintf("unknown category %q", r.Category))
	}
	if f.dir == store.PendingDir && r.Category != store.Employer {
		reasons = append(reasons, "only employer signatures can be pending")
	}
	return reasons
}

// readAll parses every file in signatures/ and pending/. Files it cannot
// use are reported as problems; an I/O error stops it. Without keepPII the
// sealed personal data is cut down to its first line, all the checks look
// at, so a run over many records does not hold every sealed block at once.
func readAll(dir string, add func(path, reason string), keepPII bool) ([]file, error) {
	var files []file
	for _, sub := range []string{store.SignedDir, store.PendingDir} {
		entries, err := os.ReadDir(filepath.Join(dir, sub))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		for _, e := range entries {
			rel := sub + "/" + e.Name()
			// Left behind by a write that was interrupted before its
			// rename; the record it was for is unchanged.
			if strings.HasSuffix(e.Name(), ".tmp") && !e.IsDir() {
				continue
			}
			if e.IsDir() {
				add(rel, "unexpected directory")
				continue
			}
			name, ok := strings.CutSuffix(e.Name(), ".json")
			id, err := strconv.ParseInt(name, 10, 64)
			if !ok || err != nil || id <= 0 {
				add(rel, "not named <account id>.json, so the service ignores it")
				continue
			}
			data, err := os.ReadFile(filepath.Join(dir, sub, e.Name()))
			if err != nil {
				return nil, err
			}
			var rec store.Record
			if err := strictJSON(data, &rec); err != nil {
				add(rel, "does not parse: "+err.Error())
				continue
			}
			if !keepPII {
				rec.PII, _, _ = strings.Cut(rec.PII, "\n")
			}
			files = append(files, file{path: rel, dir: sub, id: id, rec: rec, digest: audit.Digest(data)})
		}
	}
	slices.SortFunc(files, func(a, b file) int { return strings.Compare(a.path, b.path) })
	return files, nil
}

// strictJSON refuses unknown fields: rewriting a record that has fields this
// version does not know would silently drop them.
func strictJSON(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

// Rekey re-encrypts the personal data of every record not already sealed to
// sealer's key: it opens it with identities (the old private keys), seals it
// to the new public key and updates key_id. Other fields are left as they
// are. With dryRun nothing is written. Each re-encrypted record gets an
// audit event.
//
// It first checks every record and decrypts every one that needs re-keying,
// and stops before writing anything if one fails, so a wrong key changes
// nothing. It then writes in batches, letting go of the lock between them,
// so the service keeps signing meanwhile. A record that changed since it was
// read is left for the next run; records already on the new key are skipped,
// so a run that stopped halfway, or one after the service switched keys,
// can be run again.
func Rekey(dir string, identities []age.Identity, sealer *seal.Sealer, dryRun bool) (changed int, err error) {
	type todo struct {
		f file
		p seal.Personal
	}
	var work []todo
	err = func() error {
		unlock, err := audit.Lock(dir)
		if err != nil {
			return err
		}
		defer unlock()
		if _, err := store.RecoverJournal(dir); err != nil {
			return err
		}
		report, err := verify(dir, nil)
		if err != nil {
			return err
		}
		if !report.OK() {
			return fmt.Errorf("%d problems found; run verify and fix them first", len(report.Problems))
		}
		files, err := readAll(dir, func(string, string) {}, true)
		if err != nil {
			return err
		}
		for _, f := range files {
			if f.rec.KeyID == sealer.KeyID() {
				continue
			}
			p, err := seal.Open(f.rec.PII, identities...)
			if err != nil {
				return fmt.Errorf("%s: personal data does not decrypt with the old keys; nothing was changed", f.path)
			}
			work = append(work, todo{f, p})
		}
		return nil
	}()
	if err != nil || dryRun {
		return len(work), err
	}

	err = inBatches(dir, len(work), func(start, end int) ([]change, error) {
		var changes []change
		for _, w := range work[start:end] {
			path := filepath.Join(dir, filepath.FromSlash(w.f.path))
			current, err := os.ReadFile(path)
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if err != nil {
				return nil, err
			}
			if audit.Digest(current) != w.f.digest {
				continue
			}
			sealed, err := sealer.Seal(w.p)
			if err != nil {
				return nil, err
			}
			rec := w.f.rec
			rec.PII, rec.KeyID = sealed, sealer.KeyID()
			changes = append(changes, change{path: path, rec: rec, action: audit.Rekeyed})
		}
		changed += len(changes)
		return changes, nil
	})
	return changed, err
}

// batchSize is how many records a long job changes per hold of the lock.
// A batch takes well under a second, so a signing waits at most that long.
const batchSize = 100

// change is one record write in a batch.
type change struct {
	path   string
	rec    store.Record
	action string
}

// inBatches calls fn for consecutive ranges of n items, and applies the
// changes it returns, each batch under the lock and after checking what was
// appended to the log since the previous batch.
func inBatches(dir string, n int, fn func(start, end int) ([]change, error)) error {
	logPath := filepath.Join(dir, filepath.FromSlash(store.AuditLog))
	var chain audit.Chain
	for start := 0; start < n; start += batchSize {
		err := func() error {
			unlock, err := audit.Lock(dir)
			if err != nil {
				return err
			}
			defer unlock()
			if _, err := store.RecoverJournal(dir); err != nil {
				return err
			}
			if chain, err = audit.ScanFrom(logPath, chain, nil); err != nil {
				return fmt.Errorf("the audit log is broken, refusing to add to it: %w", err)
			}
			changes, err := fn(start, min(start+batchSize, n))
			if err != nil {
				return err
			}
			return applyBatch(dir, logPath, changes)
		}()
		if err != nil {
			return err
		}
	}
	return nil
}

// applyBatch writes the records, syncs each directory once and appends all
// their events in one write. Under a journal: any record whose event did not
// land is put back as it was, even if the process dies first.
func applyBatch(dir, logPath string, changes []change) error {
	if len(changes) == 0 {
		return nil
	}
	groups := make([][]string, len(changes))
	for i, c := range changes {
		groups[i] = []string{c.path}
	}
	return store.Journaled(dir, groups, func() error {
		dirs := map[string]bool{}
		events := make([]audit.Event, 0, len(changes))
		for _, c := range changes {
			digest, err := store.WriteRecordFile(c.path, c.rec)
			if err != nil {
				return err
			}
			dirs[filepath.Dir(c.path)] = true
			events = append(events, audit.Event{Action: c.action, Subject: c.rec.Subject(), Actor: actor, Digest: digest})
		}
		for d := range dirs {
			if err := store.SyncDir(d); err != nil {
				return err
			}
		}
		_, err := audit.AppendAll(logPath, events)
		return err
	})
}

// actor names cla-tool in the audit log.
const actor = "cla-tool"

func logEvent(dir, action, subject, digest string) error {
	_, err := audit.Append(filepath.Join(dir, filepath.FromSlash(store.AuditLog)), audit.Event{
		Action: action, Subject: subject, Actor: actor, Digest: digest,
	})
	return err
}
