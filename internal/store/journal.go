package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"

	"github.com/rotki/cla/internal/audit"
)

// JournalFile records a change in progress. A record file is changed before
// its audit event is appended, so a process that dies in between would
// leave a record no event accounts for, counted as signed. The journal holds
// the files' earlier contents; whoever takes the lock next puts back every
// change whose event did not land.
const JournalFile = "journal.json"

// maxJournaled bounds a file the journal keeps; a record is a few kilobytes.
const maxJournaled = 1 << 20

type journal struct {
	// Events is how many events the log held before the change.
	Events int64 `json:"events"`
	// Groups are the files each event covers, in the order the events are
	// appended.
	Groups [][]journalFile `json:"groups"`
}

type journalFile struct {
	Path string `json:"path"`
	// Before is the file's earlier content, nil when it did not exist.
	Before []byte `json:"before"`
}

// Journaled runs fn, which changes files and appends one audit event per
// group, in order. The caller holds the lock. Each group's files are put
// back as they were unless its event landed, whether fn fails or the
// process dies first; in the second case the next RecoverJournal does it.
// When fn's error came after every event landed (the append wrote, its sync
// failed), the changes stand and Journaled returns nil.
func Journaled(dir string, groups [][]string, fn func() error) error {
	j, err := beginJournal(dir, groups)
	if err != nil {
		return err
	}
	fnErr := fn()
	undone, err := settle(dir, j)
	if err != nil {
		return errors.Join(fnErr, err)
	}
	if fnErr != nil && undone == 0 && len(groups) > 0 {
		slog.Warn("audit events were written although the change reported an error; keeping it", "error", fnErr)
		return nil
	}
	return fnErr
}

// beginJournal records the files' contents and the log's length, durably,
// before anything is changed.
func beginJournal(dir string, groups [][]string) (journal, error) {
	j := journal{Groups: make([][]journalFile, len(groups))}
	last, _, err := audit.Last(filepath.Join(dir, filepath.FromSlash(AuditLog)))
	if err != nil {
		return j, err
	}
	j.Events = last.Seq
	for i, paths := range groups {
		for _, path := range paths {
			rel, err := filepath.Rel(dir, path)
			if err != nil || !filepath.IsLocal(rel) {
				return j, fmt.Errorf("journaled path %s is outside the data directory", path)
			}
			// Not through a symlink: putting the file back would copy
			// whatever it points at into the data directory.
			before, err := readSmallFile(path, maxJournaled)
			if err != nil && !errors.Is(err, os.ErrNotExist) {
				return j, fmt.Errorf("%s: %w", rel, err)
			}
			j.Groups[i] = append(j.Groups[i], journalFile{Path: filepath.ToSlash(rel), Before: before})
		}
	}
	data, err := json.Marshal(j)
	if err != nil {
		return j, err
	}
	return j, WriteFile(filepath.Join(dir, JournalFile), data)
}

// RecoverJournal finishes a change a process left behind when it died, as
// Journaled would have. The caller holds the lock, so no other process is
// in the middle of it. It reports how many changes it put back.
func RecoverJournal(dir string) (int, error) {
	data, err := os.ReadFile(filepath.Join(dir, JournalFile))
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	var j journal
	if err := json.Unmarshal(data, &j); err != nil {
		return 0, fmt.Errorf("parsing %s: %w", JournalFile, err)
	}
	undone, err := settle(dir, j)
	if err != nil {
		return undone, err
	}
	slog.Warn("finished a change an earlier process left behind", "undone", undone, "kept", len(j.Groups)-undone)
	return undone, nil
}

// settle puts back the groups whose events are not in the log, then removes
// the journal. It returns how many groups it put back.
func settle(dir string, j journal) (int, error) {
	last, _, err := audit.Last(filepath.Join(dir, filepath.FromSlash(AuditLog)))
	if err != nil {
		return 0, err
	}
	landed := last.Seq - j.Events
	if landed < 0 {
		// The log is shorter than when the change began: something rewrote
		// it. Leave everything for an operator, journal included.
		return 0, fmt.Errorf("the audit log lost events since %s was written", JournalFile)
	}
	undo := j.Groups[min(int(landed), len(j.Groups)):]
	dirs := map[string]bool{}
	var errs []error
	for _, group := range slices.Backward(undo) {
		for _, f := range slices.Backward(group) {
			path := filepath.Join(dir, filepath.FromSlash(f.Path))
			if f.Before == nil {
				if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
					errs = append(errs, err)
				}
			} else if err := writeFile(path, f.Before); err != nil {
				errs = append(errs, err)
			}
			dirs[filepath.Dir(path)] = true
		}
	}
	for d := range dirs {
		errs = append(errs, SyncDir(d))
	}
	if err := errors.Join(errs...); err != nil {
		// The journal stays, so the next lock holder tries again.
		return len(undo), err
	}
	if err := os.Remove(filepath.Join(dir, JournalFile)); err != nil {
		return len(undo), err
	}
	return len(undo), SyncDir(dir)
}
