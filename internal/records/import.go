package records

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/rotki/cla/internal/audit"
	"github.com/rotki/cla/internal/seal"
	"github.com/rotki/cla/internal/store"
)

// claAssistantRecord is one entry of cla-assistant's /api/cla/getAll.
type claAssistantRecord struct {
	User         string          `json:"user"`
	UserID       json.RawMessage `json:"userId"`
	CreatedAt    time.Time       `json:"created_at"`
	RevokedAt    time.Time       `json:"revoked_at"`
	GistVersion  string          `json:"gist_version"`
	CustomFields string          `json:"custom_fields"`
}

// ImportResult counts what Import did.
type ImportResult struct {
	Written  int
	Existing int
	Skipped  int
}

// Import writes signatures/<id>.json under dir for every signer in a
// cla-assistant export, sealing their name and email like the service does.
// Each account keeps its earliest signature that was not revoked. Existing
// files are never overwritten. Entries without a usable account ID are
// skipped and counted.
func Import(export []byte, dir string, sealer *seal.Sealer) (ImportResult, error) {
	var res ImportResult
	var entries []claAssistantRecord
	if err := json.Unmarshal(export, &entries); err != nil {
		return res, fmt.Errorf("parsing the export: %w", err)
	}

	earliest := map[int64]claAssistantRecord{}
	for _, e := range entries {
		// cla-assistant stores the ID as a string; accept a number too.
		var id int64
		if _, err := fmt.Sscan(strings.Trim(string(e.UserID), `"`), &id); err != nil || id <= 0 || !e.RevokedAt.IsZero() {
			res.Skipped++
			continue
		}
		if prev, ok := earliest[id]; !ok || e.CreatedAt.Before(prev.CreatedAt) {
			earliest[id] = e
		}
	}

	if err := os.MkdirAll(dir, 0o750); err != nil {
		return res, err
	}
	ids := slices.Sorted(maps.Keys(earliest))
	err := inBatches(dir, len(ids), func(start, end int) ([]change, error) {
		var changes []change
		for _, id := range ids[start:end] {
			// Checked under the lock, so a signature the service writes
			// meanwhile is never overwritten.
			if exists, err := hasRecord(dir, id); err != nil {
				return nil, err
			} else if exists {
				res.Existing++
				continue
			}
			rec, err := imported(id, earliest[id], sealer)
			if err != nil {
				return nil, err
			}
			changes = append(changes, change{path: filepath.Join(dir, filepath.FromSlash(store.RecordPath(store.SignedDir, id))), rec: rec, action: audit.Imported})
		}
		res.Written += len(changes)
		return changes, nil
	})
	return res, err
}

// hasRecord reports whether the account already has a signed or pending
// record.
func hasRecord(dir string, id int64) (bool, error) {
	for _, sub := range []string{store.SignedDir, store.PendingDir} {
		_, err := os.Stat(filepath.Join(dir, filepath.FromSlash(store.RecordPath(sub, id))))
		if err == nil {
			return true, nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return false, err
		}
	}
	return false, nil
}

// imported builds the record for one cla-assistant signature.
func imported(id int64, e claAssistantRecord, sealer *seal.Sealer) (store.Record, error) {
	var fields struct {
		Name     string `json:"name"`
		Email    string `json:"email"`
		Category string `json:"category"`
	}
	_ = json.Unmarshal([]byte(e.CustomFields), &fields)
	sealed, err := sealer.Seal(seal.Personal{Name: fields.Name, Email: fields.Email})
	if err != nil {
		return store.Record{}, err
	}
	// cla-assistant only knows the repo someone signed in, not the pull
	// request, so pr stays empty rather than holding something else.
	rec := store.Record{
		GitHubID:    id,
		Login:       e.User,
		SignedAt:    e.CreatedAt.UTC(),
		CLARevision: e.GistVersion,
		Category:    store.Individual,
		Origin:      "cla-assistant",
		KeyID:       sealer.KeyID(),
		PII:         sealed,
		Salt:        audit.NewSalt(),
	}
	if strings.Contains(strings.ToLower(fields.Category), "employer") {
		rec.Category = store.Employer
		rec.ConfirmedBy = "cla-assistant import"
	}
	return rec, nil
}
