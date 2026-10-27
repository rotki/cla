package records

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"filippo.io/age"

	"github.com/rotki/cla/internal/audit"
	"github.com/rotki/cla/internal/seal"
	"github.com/rotki/cla/internal/store"
)

type key struct {
	identity *age.X25519Identity
	sealer   *seal.Sealer
}

func newKey(t *testing.T, id string) key {
	t.Helper()
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	sealer, err := seal.New(identity.Recipient().String(), id)
	if err != nil {
		t.Fatal(err)
	}
	return key{identity, sealer}
}

func write(t *testing.T, dir, rel, content string) {
	t.Helper()
	path := filepath.Join(dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func record(t *testing.T, k key, rec store.Record, p seal.Personal) store.Record {
	t.Helper()
	sealed, err := k.sealer.Seal(p)
	if err != nil {
		t.Fatal(err)
	}
	rec.PII = sealed
	rec.KeyID = k.sealer.KeyID()
	if rec.SignedAt.IsZero() {
		rec.SignedAt = time.Date(2026, 10, 26, 10, 0, 0, 0, time.UTC)
	}
	if rec.CLARevision == "" {
		rec.CLARevision = "rev1"
	}
	if rec.Origin == "" {
		rec.Origin = "rotki-cla"
	}
	if rec.Salt == "" {
		rec.Salt = audit.NewSalt()
	}
	return rec
}

// put writes a record the way the service does: the file, then its event.
func put(t *testing.T, dir, sub, action string, rec store.Record) {
	t.Helper()
	digest, err := store.WriteRecord(filepath.Join(dir, filepath.FromSlash(store.RecordPath(sub, rec.GitHubID))), rec)
	if err != nil {
		t.Fatal(err)
	}
	if err := logEvent(dir, action, rec.Subject(), digest); err != nil {
		t.Fatal(err)
	}
}

// settings writes config.json and grandfathered.json and logs them.
func settings(t *testing.T, dir, config, grandfathered string) {
	t.Helper()
	write(t, dir, store.ConfigFile, config)
	if grandfathered != "" {
		write(t, dir, store.Grandfathered, grandfathered)
	}
	if err := store.LogFileChanges(dir, "test", time.Now()); err != nil {
		t.Fatal(err)
	}
}

func writeRec(t *testing.T, dir, sub string, rec store.Record) {
	t.Helper()
	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	write(t, dir, filepath.ToSlash(filepath.Join(sub, jsonName(rec.GitHubID))), string(data)+"\n")
}

func jsonName(id int64) string {
	return strconv.FormatInt(id, 10) + ".json"
}

// dataDir builds a valid data directory sealed to k, with its audit log.
func dataDir(t *testing.T, k key) string {
	t.Helper()
	dir := t.TempDir()
	settings(t, dir, `{"cla_gist":"g","cla_revision":"rev1","allowlist":[],"exempt_team":"core"}`, `[1, 2, 3]`)
	put(t, dir, store.SignedDir, audit.Signed, record(t, k, store.Record{GitHubID: 100, Login: "alice", Category: store.Individual, PR: "rotki/rotki#1"}, seal.Personal{Name: "Alice", Email: "alice@example.com"}))
	put(t, dir, store.SignedDir, audit.Confirmed, record(t, k, store.Record{GitHubID: 200, Login: "bob", Category: store.Employer, Company: "ACME", Role: "CTO", ConfirmedBy: "admin", ConfirmedAt: time.Date(2026, 10, 27, 0, 0, 0, 0, time.UTC)}, seal.Personal{Name: "Bob", Email: "bob@acme.example"}))
	put(t, dir, store.PendingDir, audit.Pending, record(t, k, store.Record{GitHubID: 300, Login: "carol", Category: store.Employer, Company: "Example GmbH", Role: "Lead"}, seal.Personal{Name: "Carol", Email: "carol@example.com"}))
	return dir
}

func TestVerifyAcceptsAValidDataDir(t *testing.T) {
	k := newKey(t, "2026-01")
	dir := dataDir(t, k)

	report, err := Verify(dir, []age.Identity{k.identity})
	if err != nil {
		t.Fatal(err)
	}
	if !report.OK() || report.Records != 3 || report.Decrypted != 3 || report.Grandfathered != 3 || report.ByKey["2026-01"] != 3 || report.Events != 5 || report.Head == "" {
		t.Fatalf("report %+v", report)
	}

	// Without a key only the structure is checked.
	report, _ = Verify(dir, nil)
	if !report.OK() || report.Decrypted != 0 {
		t.Fatalf("structural report %+v", report)
	}
}

func TestVerifyFindsProblems(t *testing.T) {
	k := newKey(t, "2026-01")
	other := newKey(t, "other")
	dir := dataDir(t, k)

	// Named for one account, written for another.
	rec := record(t, k, store.Record{GitHubID: 401, Category: store.Individual}, seal.Personal{Name: "D", Email: "d@example.com"})
	data, _ := json.MarshalIndent(rec, "", "  ")
	write(t, dir, "signatures/400.json", string(data))
	// Sealed to a key we do not hold.
	writeRec(t, dir, store.SignedDir, record(t, other, store.Record{GitHubID: 500, Category: store.Individual}, seal.Personal{Name: "E", Email: "e@example.com"}))
	// Plain text where the sealed block belongs.
	plain := record(t, k, store.Record{GitHubID: 600, Category: store.Individual}, seal.Personal{})
	plain.PII = `{"name":"F","email":"f@example.com"}`
	writeRec(t, dir, store.SignedDir, plain)
	// An employer signature confirmed by nobody, and an individual one pending.
	writeRec(t, dir, store.SignedDir, record(t, k, store.Record{GitHubID: 700, Category: store.Employer, Company: "X", Role: "Y"}, seal.Personal{Name: "G", Email: "g@example.com"}))
	writeRec(t, dir, store.PendingDir, record(t, k, store.Record{GitHubID: 800, Category: store.Individual}, seal.Personal{Name: "H", Email: "h@example.com"}))
	// The same account both signed and pending.
	writeRec(t, dir, store.PendingDir, record(t, k, store.Record{GitHubID: 100, Category: store.Employer, Company: "X", Role: "Y"}, seal.Personal{Name: "A", Email: "a@example.com"}))
	// A field this version does not know, and a stray file.
	write(t, dir, "signatures/900.json", `{"github_id":900,"surprise":true}`)
	write(t, dir, "signatures/notes.txt", "hello")

	report, err := Verify(dir, []age.Identity{k.identity})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"signatures/400.json":  "does not match the file name",
		"signatures/500.json":  "does not decrypt",
		"signatures/600.json":  "not an armored age file",
		"signatures/700.json":  "needs confirmed_by",
		"pending/800.json":     "only employer signatures can be pending",
		"signatures/100.json":  "also has pending/100.json",
		"signatures/900.json":  "does not parse",
		"signatures/notes.txt": "not named <account id>.json",
	}
	for path, reason := range want {
		found := false
		for _, p := range report.Problems {
			if p.Path == path && strings.Contains(p.Reason, reason) {
				found = true
			}
		}
		if !found {
			t.Errorf("no problem %q for %s; got %v", reason, path, report.Problems)
		}
	}
	for _, p := range report.Problems {
		if strings.Contains(p.Reason, "example.com") {
			t.Fatalf("a report leaks personal data: %v", p)
		}
	}
}

func TestRekey(t *testing.T) {
	oldKey := newKey(t, "2026-01")
	newK := newKey(t, "2027-01")
	dir := dataDir(t, oldKey)
	before, _ := os.ReadFile(filepath.Join(dir, store.SignedDir, "200.json"))

	// A dry run counts and writes nothing.
	n, err := Rekey(dir, []age.Identity{oldKey.identity}, newK.sealer, true)
	if err != nil || n != 3 {
		t.Fatalf("dry run: %d %v", n, err)
	}
	if after, _ := os.ReadFile(filepath.Join(dir, store.SignedDir, "200.json")); string(after) != string(before) {
		t.Fatal("a dry run changed a file")
	}

	n, err = Rekey(dir, []age.Identity{oldKey.identity}, newK.sealer, false)
	if err != nil || n != 3 {
		t.Fatalf("rekey: %d %v", n, err)
	}

	// Everything opens with the new key, and only with it.
	report, _ := Verify(dir, []age.Identity{newK.identity})
	if !report.OK() || report.Decrypted != 3 || report.ByKey["2027-01"] != 3 {
		t.Fatalf("after rekey: %+v", report)
	}
	if report, _ := Verify(dir, []age.Identity{oldKey.identity}); report.OK() {
		t.Fatal("the old key still opens the records")
	}

	// The personal data and every other field are unchanged.
	var rec store.Record
	data, _ := os.ReadFile(filepath.Join(dir, store.SignedDir, "200.json"))
	if err := json.Unmarshal(data, &rec); err != nil {
		t.Fatal(err)
	}
	p, err := seal.Open(rec.PII, newK.identity)
	if err != nil || p.Name != "Bob" || p.Email != "bob@acme.example" {
		t.Fatalf("personal data after rekey: %+v %v", p, err)
	}
	if rec.Company != "ACME" || rec.Role != "CTO" || rec.ConfirmedBy != "admin" || rec.Login != "bob" || rec.KeyID != "2027-01" {
		t.Fatalf("fields after rekey: %+v", rec)
	}

	// A second run has nothing to do.
	if n, err := Rekey(dir, []age.Identity{oldKey.identity}, newK.sealer, false); err != nil || n != 0 {
		t.Fatalf("second run: %d %v", n, err)
	}
}

func TestRekeyResumesAfterAPartialRun(t *testing.T) {
	oldKey := newKey(t, "2026-01")
	newK := newKey(t, "2027-01")
	dir := dataDir(t, oldKey)

	// One record was already moved before the run stopped.
	alice, _ := store.ReadRecord(filepath.Join(dir, "signatures", "100.json"))
	put(t, dir, store.SignedDir, audit.Rekeyed, record(t, newK, store.Record{GitHubID: 100, Login: "alice", Category: store.Individual, Salt: alice.Salt}, seal.Personal{Name: "Alice", Email: "alice@example.com"}))

	n, err := Rekey(dir, []age.Identity{oldKey.identity}, newK.sealer, false)
	if err != nil || n != 2 {
		t.Fatalf("resumed rekey: %d %v", n, err)
	}
	if report, _ := Verify(dir, []age.Identity{newK.identity}); !report.OK() || report.Decrypted != 3 {
		t.Fatalf("after resume: %+v", report)
	}
}

func TestRekeyWithAWrongKeyChangesNothing(t *testing.T) {
	oldKey := newKey(t, "2026-01")
	wrong := newKey(t, "wrong")
	newK := newKey(t, "2027-01")
	dir := dataDir(t, oldKey)
	before := snapshot(t, dir)

	if _, err := Rekey(dir, []age.Identity{wrong.identity}, newK.sealer, false); err == nil || !strings.Contains(err.Error(), "nothing was changed") {
		t.Fatalf("got %v", err)
	}
	if after := snapshot(t, dir); after != before {
		t.Fatal("a failed rekey changed files")
	}
}

func TestRekeyRefusesABrokenDataDir(t *testing.T) {
	oldKey := newKey(t, "2026-01")
	newK := newKey(t, "2027-01")
	dir := dataDir(t, oldKey)
	write(t, dir, "signatures/900.json", `{"github_id":900,"surprise":true}`)
	if _, err := Rekey(dir, []age.Identity{oldKey.identity}, newK.sealer, false); err == nil || !strings.Contains(err.Error(), "problems found") {
		t.Fatalf("got %v", err)
	}
}

func snapshot(t *testing.T, dir string) string {
	t.Helper()
	var b strings.Builder
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || d.Name() == ".lock" {
			return err
		}
		data, err := os.ReadFile(path)
		b.WriteString(path + "\n" + string(data) + "\n")
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return b.String()
}

func TestImport(t *testing.T) {
	k := newKey(t, "2026-01")
	dir := t.TempDir()
	settings(t, dir, `{"cla_gist":"g","cla_revision":"rev1"}`, "")
	export := `[
	  {"user":"alice","userId":"100","created_at":"2020-05-01T10:00:00Z","gist_version":"v1","repo":"rotki","owner":"rotkehlchenio",
	   "custom_fields":"{\"name\":\"Alice\",\"email\":\"alice@example.com\",\"category\":\"I am signing on behalf of myself.\"}"},
	  {"user":"alice","userId":"100","created_at":"2019-01-01T10:00:00Z","gist_version":"v0",
	   "custom_fields":"{\"name\":\"Alice\",\"email\":\"alice@example.com\"}"},
	  {"user":"bob","userId":200,"created_at":"2021-01-01T10:00:00Z","gist_version":"v1",
	   "custom_fields":"{\"name\":\"Bob\",\"email\":\"bob@acme.example\",\"category\":\"I am signing on behalf of my employer.\"}"},
	  {"user":"revoked","userId":"300","created_at":"2021-01-01T10:00:00Z","revoked_at":"2022-01-01T10:00:00Z","gist_version":"v1","custom_fields":"{}"},
	  {"user":"ghost","userId":"","created_at":"2021-01-01T10:00:00Z","custom_fields":"{}"}
	]`

	res, err := Import([]byte(export), dir, k.sealer)
	if err != nil {
		t.Fatal(err)
	}
	if res.Written != 2 || res.Skipped != 2 || res.Existing != 0 {
		t.Fatalf("result %+v", res)
	}

	var alice store.Record
	data, _ := os.ReadFile(filepath.Join(dir, store.SignedDir, "100.json"))
	if err := json.Unmarshal(data, &alice); err != nil {
		t.Fatal(err)
	}
	if alice.CLARevision != "v0" || alice.SignedAt.Year() != 2019 || alice.Origin != "cla-assistant" || alice.PR != "" {
		t.Fatalf("alice kept the wrong signature: %+v", alice)
	}
	if strings.Contains(string(data), "alice@example.com") {
		t.Fatal("imported personal data is in plain text")
	}

	var bob store.Record
	data, _ = os.ReadFile(filepath.Join(dir, store.SignedDir, "200.json"))
	_ = json.Unmarshal(data, &bob)
	if bob.Category != store.Employer || bob.ConfirmedBy != "cla-assistant import" {
		t.Fatalf("bob: %+v", bob)
	}

	// The import passes verify, and a second import changes nothing.
	if report, _ := Verify(dir, []age.Identity{k.identity}); !report.OK() || report.Decrypted != 2 {
		t.Fatalf("verify after import: %+v", report)
	}
	before := snapshot(t, dir)
	res, err = Import([]byte(export), dir, k.sealer)
	if err != nil || res.Written != 0 || res.Existing != 2 {
		t.Fatalf("second import: %+v %v", res, err)
	}
	if snapshot(t, dir) != before {
		t.Fatal("a second import changed files")
	}
}

func TestVerifyChecksTheAuditTrail(t *testing.T) {
	k := newKey(t, "2026-01")

	t.Run("edited record", func(t *testing.T) {
		dir := dataDir(t, k)
		rec, _ := store.ReadRecord(filepath.Join(dir, "signatures", "100.json"))
		rec.CLARevision = "rev0"
		if _, err := store.WriteRecord(filepath.Join(dir, "signatures", "100.json"), rec); err != nil {
			t.Fatal(err)
		}
		expectProblem(t, dir, "signatures/100.json", "changed outside the service")
	})
	t.Run("added record", func(t *testing.T) {
		dir := dataDir(t, k)
		writeRec(t, dir, store.SignedDir, record(t, k, store.Record{GitHubID: 500, Category: store.Individual}, seal.Personal{Name: "E", Email: "e@example.com"}))
		expectProblem(t, dir, "signatures/500.json", "has no audit event")
	})
	t.Run("deleted record", func(t *testing.T) {
		dir := dataDir(t, k)
		if err := os.Remove(filepath.Join(dir, "pending", "300.json")); err != nil {
			t.Fatal(err)
		}
		expectProblem(t, dir, store.AuditLog, "deleted outside cla-tool")
	})
	t.Run("edited settings", func(t *testing.T) {
		dir := dataDir(t, k)
		write(t, dir, store.Grandfathered, `[1, 2, 3, 4]`)
		expectProblem(t, dir, store.Grandfathered, "changed since its last audit event")
	})
	t.Run("edited log", func(t *testing.T) {
		dir := dataDir(t, k)
		path := filepath.Join(dir, filepath.FromSlash(store.AuditLog))
		data, _ := os.ReadFile(path)
		write(t, dir, store.AuditLog, strings.Replace(string(data), `"actor":"cla-tool"`, `"actor":"admin:x"`, 1))
		expectProblem(t, dir, store.AuditLog, "the log was edited")
	})
}

func expectProblem(t *testing.T, dir, path, reason string) {
	t.Helper()
	report, err := Verify(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range report.Problems {
		if p.Path == path && strings.Contains(p.Reason, reason) {
			return
		}
	}
	t.Fatalf("no problem %q for %s; got %v", reason, path, report.Problems)
}

func TestCheckAnchor(t *testing.T) {
	k := newKey(t, "2026-01")
	dir := dataDir(t, k)
	report, _ := Verify(dir, nil)
	if err := CheckAnchor(dir, int64(report.Events), report.Head); err != nil {
		t.Fatal(err)
	}

	// The log is rebuilt from scratch: consistent, but not what was anchored.
	if err := os.Remove(filepath.Join(dir, filepath.FromSlash(store.AuditLog))); err != nil {
		t.Fatal(err)
	}
	if err := store.LogFileChanges(dir, "forger", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := CheckAnchor(dir, 2, report.Head); err == nil {
		t.Fatal("a rebuilt log matched the anchor")
	}
	if err := CheckAnchor(dir, int64(report.Events), report.Head); err == nil || !strings.Contains(err.Error(), "truncated") {
		t.Fatalf("got %v", err)
	}
}

func TestImportLeavesPendingAccountsAlone(t *testing.T) {
	k := newKey(t, "2026-01")
	dir := dataDir(t, k)
	export := `[{"user":"carol","userId":"300","created_at":"2020-01-01T10:00:00Z","gist_version":"v1","custom_fields":"{}"},
	            {"user":"dave","userId":"400","created_at":"2020-01-01T10:00:00Z","gist_version":"v1","custom_fields":"{}"}]`
	res, err := Import([]byte(export), dir, k.sealer)
	if err != nil || res.Written != 1 || res.Existing != 1 {
		t.Fatalf("import: %+v %v", res, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "signatures", "300.json")); err == nil {
		t.Fatal("a pending account was imported as signed")
	}
	if report, _ := Verify(dir, nil); !report.OK() {
		t.Fatalf("after import: %v", report.Problems)
	}
}

func TestImportRunsAlongsideTheService(t *testing.T) {
	k := newKey(t, "2026-01")
	dir := dataDir(t, k)
	var entries []string
	for id := 1000; id < 1000+3*batchSize; id++ {
		entries = append(entries, `{"user":"u","userId":"`+strconv.Itoa(id)+`","created_at":"2020-01-01T10:00:00Z","gist_version":"v1","custom_fields":"{}"}`)
	}
	st := store.New(dir)
	if err := st.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() {
		_, err := Import([]byte("["+strings.Join(entries, ",")+"]"), dir, k.sealer)
		done <- err
	}()
	// Signings land between the import's batches.
	for id := int64(5000); id < 5010; id++ {
		if err := st.Create(context.Background(), store.Record{GitHubID: id, Category: store.Individual, SignedAt: time.Now(), CLARevision: "rev1", Origin: "rotki-cla", KeyID: "2026-01", PII: "-----BEGIN AGE ENCRYPTED FILE-----"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	report, err := Verify(dir, nil)
	if err != nil || report.Records != 3+3*batchSize+10 {
		t.Fatalf("%d records, %v", report.Records, err)
	}
	for _, p := range report.Problems {
		if p.Path == store.AuditLog {
			t.Fatalf("the chain forked: %v", p)
		}
	}
}

func TestABatchWhoseAppendFailsIsUndone(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores file permissions")
	}
	oldKey := newKey(t, "2026-01")
	newK := newKey(t, "2027-01")
	dir := dataDir(t, oldKey)
	before := snapshot(t, dir)
	logPath := filepath.Join(dir, filepath.FromSlash(store.AuditLog))
	if err := os.Chmod(logPath, 0o400); err != nil {
		t.Fatal(err)
	}
	if _, err := Rekey(dir, []age.Identity{oldKey.identity}, newK.sealer, false); err == nil {
		t.Fatal("rekey succeeded without its events")
	}
	_ = os.Chmod(logPath, 0o640)
	if snapshot(t, dir) != before {
		t.Fatal("the records were left changed without events")
	}
}

// crash leaves dir as a process killed inside store.Journaled would: the
// journal written, change made, and no event for it.
func crash(t *testing.T, dir string, paths []string, change func()) {
	t.Helper()
	var journal []byte
	_ = store.Journaled(dir, [][]string{paths}, func() error {
		var err error
		journal, err = os.ReadFile(filepath.Join(dir, store.JournalFile))
		if err != nil {
			t.Fatal(err)
		}
		return errors.New("killed")
	})
	change()
	write(t, dir, store.JournalFile, string(journal))
}

func TestCLAToolFinishesAnInterruptedChange(t *testing.T) {
	k := newKey(t, "2026-01")
	dir := dataDir(t, k)
	path := filepath.Join(dir, filepath.FromSlash(store.RecordPath(store.SignedDir, 900)))
	crash(t, dir, []string{path}, func() {
		writeRec(t, dir, store.SignedDir, record(t, k, store.Record{GitHubID: 900, Login: "mallory", Category: store.Individual}, seal.Personal{Name: "M", Email: "m@example.com"}))
	})

	// Verify only reports it.
	report, err := Verify(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	var sawJournal bool
	for _, p := range report.Problems {
		sawJournal = sawJournal || p.Path == store.JournalFile
	}
	if !sawJournal {
		t.Fatalf("the journal was not reported: %+v", report.Problems)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal("verify changed the data directory")
	}

	// Any writing command finishes it first: here rekey, which would
	// otherwise refuse a directory with problems.
	newK := newKey(t, "2027-01")
	if _, err := Rekey(dir, []age.Identity{k.identity}, newK.sealer, false); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("the record without an event is still there")
	}
	if report, err := Verify(dir, nil); err != nil || !report.OK() {
		t.Fatalf("after rekey: %+v %v", report, err)
	}
}

func TestImportFinishesAnInterruptedChange(t *testing.T) {
	k := newKey(t, "2026-01")
	dir := dataDir(t, k)
	path := filepath.Join(dir, filepath.FromSlash(store.RecordPath(store.SignedDir, 900)))
	crash(t, dir, []string{path}, func() {
		writeRec(t, dir, store.SignedDir, record(t, k, store.Record{GitHubID: 900, Login: "mallory", Category: store.Individual}, seal.Personal{Name: "M", Email: "m@example.com"}))
	})
	export := `[{"user":"dave","userId":"400","created_at":"2020-05-01T10:00:00Z","gist_version":"v1",
	  "custom_fields":"{\"name\":\"Dave\",\"email\":\"dave@example.com\",\"category\":\"I am signing on behalf of myself.\"}"}]`
	if _, err := Import([]byte(export), dir, k.sealer); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("the record without an event is still there")
	}
	if report, err := Verify(dir, nil); err != nil || !report.OK() || report.Records != 4 {
		t.Fatalf("after import: %+v %v", report, err)
	}
}
