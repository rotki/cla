package store

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/rotki/cla/internal/audit"
)

func write(t *testing.T, dir, rel, content string) {
	t.Helper()
	path := filepath.Join(dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o640); err != nil {
		t.Fatal(err)
	}
}

func newStore(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	write(t, dir, ConfigFile, `{"cla_gist":"g","cla_revision":"r1","allowlist":["someone"]}`)
	write(t, dir, Grandfathered, `[100, 101]`)
	write(t, dir, "signatures/200.json", `{"github_id":200}`)
	write(t, dir, "pending/300.json", `{"github_id":300,"category":"employer","company":"Example GmbH","signed_at":"2026-10-01T00:00:00Z","salt":"s3"}`)
	write(t, dir, "signatures/notes.txt", "notes")
	return New(dir)
}

func events(t *testing.T, s *Store) []audit.Event {
	t.Helper()
	events, err := audit.Read(s.path(AuditLog))
	if err != nil {
		t.Fatal(err)
	}
	return events
}

func TestRefreshAndStanding(t *testing.T) {
	s := newStore(t)
	if s.Ready() {
		t.Fatal("ready before the first refresh")
	}
	if err := s.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	want := map[int64]Standing{100: GrandfatheredIn, 200: Signed, 300: Pending, 999: NotSigned}
	for id, st := range want {
		if got := s.StandingOf(id); got != st {
			t.Errorf("StandingOf(%d) = %v, want %v", id, got, st)
		}
	}
	if cfg := s.Config(); cfg.CLARevision != "r1" || cfg.Allowlist[0] != "someone" {
		t.Fatalf("config %+v", cfg)
	}
	if s.Head() == "" || s.ConfigVersion() == "" {
		t.Fatal("no audit head or config version")
	}
}

func TestSettingsChangesAreLoggedOnce(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	for range 3 {
		if err := s.Refresh(ctx); err != nil {
			t.Fatal(err)
		}
	}
	got := events(t, s)
	if len(got) != 2 || got[0].Action == got[1].Action || got[0].Actor != "service" {
		t.Fatalf("the first load logged %+v", got)
	}

	version := s.ConfigVersion()
	write(t, s.dir, ConfigFile, `{"cla_gist":"g","cla_revision":"r2"}`)
	// A new store, as after a restart, must not log the unchanged
	// grandfathered.json again.
	s2 := New(s.dir)
	if err := s2.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	got = events(t, s2)
	if len(got) != 3 || got[2].Action != audit.Config || s2.ConfigVersion() == version || s2.Config().CLARevision != "r2" {
		t.Fatalf("a hand edit was not picked up: %+v", got)
	}
}

func TestCreateIsCreateOnly(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	if err := s.Refresh(ctx); err != nil {
		t.Fatal(err)
	}

	rec := Record{GitHubID: 400, Login: "new", Category: Individual, PII: "sealed"}
	if err := s.Create(ctx, rec); err != nil {
		t.Fatal(err)
	}
	if s.StandingOf(400) != Signed {
		t.Fatal("new signature not visible after create")
	}
	written, err := ReadRecord(s.path("signatures/400.json"))
	if err != nil || written.Salt == "" {
		t.Fatalf("record %+v %v", written, err)
	}
	last := events(t, s)[2]
	data, _ := os.ReadFile(s.path("signatures/400.json"))
	if last.Action != audit.Signed || last.Subject != written.Subject() || last.Digest != audit.Digest(data) {
		t.Fatalf("event %+v", last)
	}
	if strings.Contains(last.Subject, "400") {
		t.Fatal("the event names the account")
	}

	if err := s.Create(ctx, rec); !errors.Is(err, ErrExists) {
		t.Fatalf("second create: %v", err)
	}
	if err := s.Create(ctx, Record{GitHubID: 100, Category: Individual}); !errors.Is(err, ErrExists) {
		t.Fatalf("grandfathered account created a record: %v", err)
	}

	emp := Record{GitHubID: 500, Login: "emp", Category: Employer, Company: "ACME"}
	if err := s.Create(ctx, emp); err != nil {
		t.Fatal(err)
	}
	if s.StandingOf(500) != Pending || events(t, s)[3].Action != audit.Pending {
		t.Fatal("employer signature did not land in pending/")
	}
}

func TestCreateSeesFilesWrittenSinceTheLastRefresh(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	if err := s.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	// Written behind the snapshot's back, e.g. by cla-tool import.
	write(t, s.dir, "signatures/600.json", `{"github_id":600}`)
	if err := s.Create(ctx, Record{GitHubID: 600, Category: Individual}); !errors.Is(err, ErrExists) {
		t.Fatalf("got %v", err)
	}
}

func TestConfirmAndReject(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	if err := s.Refresh(ctx); err != nil {
		t.Fatal(err)
	}

	pending, err := s.PendingRecords(ctx)
	if err != nil || len(pending) != 1 || pending[0].Company != "Example GmbH" {
		t.Fatalf("pending %+v %v", pending, err)
	}

	now := time.Date(2026, 10, 26, 0, 0, 0, 0, time.UTC)
	if err := s.Confirm(ctx, 300, pendingDigest(t, s, 300), "admin", now); err != nil {
		t.Fatal(err)
	}
	if s.StandingOf(300) != Signed {
		t.Fatal("confirmed signature not signed")
	}
	if _, err := os.Stat(s.path("pending/300.json")); !os.IsNotExist(err) {
		t.Fatal("pending file left behind")
	}
	data, _ := os.ReadFile(s.path("signatures/300.json"))
	if !strings.Contains(string(data), `"confirmed_by": "admin"`) {
		t.Fatalf("confirmation not recorded: %s", data)
	}
	if last := events(t, s)[2]; last.Action != audit.Confirmed || last.Actor != "admin:admin" || last.Digest != audit.Digest(data) {
		t.Fatalf("event %+v", last)
	}
	if err := s.Confirm(ctx, 300, pendingDigest(t, s, 300), "admin", now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("confirming twice: %v", err)
	}

	if err := s.Create(ctx, Record{GitHubID: 700, Category: Employer, Company: "X"}); err != nil {
		t.Fatal(err)
	}
	if err := s.Reject(ctx, 700, pendingDigest(t, s, 700), "admin"); err != nil {
		t.Fatal(err)
	}
	if s.StandingOf(700) != NotSigned {
		t.Fatal("rejected signature still counts")
	}
	if last := events(t, s)[4]; last.Action != audit.Rejected || last.Digest != "" {
		t.Fatalf("event %+v", last)
	}
}

func TestConfirmFinishesAnInterruptedConfirm(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	if err := s.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	// The signed record was written, then the process stopped.
	rec, _ := ReadRecord(s.path("pending/300.json"))
	rec.ConfirmedBy = "admin"
	if _, err := WriteRecord(s.path("signatures/300.json"), rec); err != nil {
		t.Fatal(err)
	}
	if err := s.Confirm(ctx, 300, pendingDigest(t, s, 300), "admin", time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(s.path("pending/300.json")); !os.IsNotExist(err) {
		t.Fatal("pending file left behind")
	}
}

func TestConfirmRefusesToReplaceADifferentSignature(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	if err := s.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	// An individual signature landed for the same account meanwhile.
	write(t, s.dir, "signatures/300.json", `{"github_id":300,"category":"individual","signed_at":"2026-01-01T00:00:00Z"}`)
	if err := s.Confirm(ctx, 300, pendingDigest(t, s, 300), "admin", time.Now()); !errors.Is(err, ErrConflict) {
		t.Fatalf("got %v", err)
	}
	if _, err := os.Stat(s.path("pending/300.json")); err != nil {
		t.Fatal("the pending signature was dropped")
	}
}

func TestABrokenLogStopsWrites(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	if err := s.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(s.path(AuditLog))
	write(t, s.dir, AuditLog, strings.Replace(string(data), `"seq":1`, `"seq":7`, 1))
	write(t, s.dir, ConfigFile, `{"cla_gist":"g","cla_revision":"r9"}`)
	if err := s.Refresh(ctx); err == nil || !strings.Contains(err.Error(), "audit log is broken") {
		t.Fatalf("got %v", err)
	}
}

// pendingDigest is the digest the admin page shows for id's pending record,
// "" when there is none.
func pendingDigest(t *testing.T, s *Store, id int64) string {
	t.Helper()
	data, err := os.ReadFile(s.path(RecordPath(PendingDir, id)))
	if os.IsNotExist(err) {
		return ""
	}
	if err != nil {
		t.Fatal(err)
	}
	return audit.Digest(data)
}

func TestADecisionOnAReplacedPendingRecordIsRefused(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	if err := s.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	seen := pendingDigest(t, s, 300)
	// Rejected by one admin, then signed again with another employer.
	if err := s.Reject(ctx, 300, seen, "first"); err != nil {
		t.Fatal(err)
	}
	if err := s.Create(ctx, Record{GitHubID: 300, Category: Employer, Company: "Other Corp"}); err != nil {
		t.Fatal(err)
	}
	// The second admin's page still shows the first record.
	if err := s.Confirm(ctx, 300, seen, "second", time.Now()); !errors.Is(err, ErrStale) {
		t.Fatalf("confirm from a stale page: %v", err)
	}
	if err := s.Reject(ctx, 300, seen, "second"); !errors.Is(err, ErrStale) {
		t.Fatalf("reject from a stale page: %v", err)
	}
	if s.StandingOf(300) != Pending {
		t.Fatal("a stale decision changed the replacement")
	}
}

// interrupt starts a journaled change of paths, makes it with change, and
// stops there, as a process killed before settling it would.
func interrupt(t *testing.T, s *Store, paths []string, change func()) {
	t.Helper()
	if _, err := beginJournal(s.dir, [][]string{paths}); err != nil {
		t.Fatal(err)
	}
	change()
}

func TestASignatureWhoseEventNeverLandedIsUndoneOnRestart(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	if err := s.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	path := s.path(RecordPath(SignedDir, 400))
	interrupt(t, s, []string{path}, func() {
		if _, err := WriteRecord(path, Record{GitHubID: 400, Category: Individual}); err != nil {
			t.Fatal(err)
		}
	})

	// A new process starts on the same directory.
	s = New(s.dir)
	if err := s.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if s.StandingOf(400) != NotSigned {
		t.Fatal("a signature without its event counts")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("the record without an event is still there")
	}
	if _, err := os.Stat(s.path(JournalFile)); !os.IsNotExist(err) {
		t.Fatal("the journal was left behind")
	}
	if err := s.Create(ctx, Record{GitHubID: 400, Category: Individual}); err != nil {
		t.Fatalf("signing again: %v", err)
	}
}

func TestASignatureWhoseEventLandedIsKeptOnRestart(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	if err := s.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	path := s.path(RecordPath(SignedDir, 400))
	rec := Record{GitHubID: 400, Category: Individual, Salt: audit.NewSalt()}
	interrupt(t, s, []string{path}, func() {
		digest, err := WriteRecord(path, rec)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := audit.Append(s.path(AuditLog), audit.Event{Action: audit.Signed, Subject: rec.Subject(), Actor: "signer", Digest: digest}); err != nil {
			t.Fatal(err)
		}
	})

	s = New(s.dir)
	if err := s.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if s.StandingOf(400) != Signed {
		t.Fatal("a signature whose event landed was undone")
	}
}

// breakLog makes the next append fail, as a full disk would.
func breakLog(t *testing.T, s *Store) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("root ignores file permissions")
	}
	if err := os.Chmod(s.path(AuditLog), 0o400); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(s.path(AuditLog), 0o640) })
}

func TestAFailedAppendLeavesNoRecordBehind(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	if err := s.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	breakLog(t, s)

	if err := s.Create(ctx, Record{GitHubID: 400, Category: Individual}); err == nil {
		t.Fatal("create succeeded without its event")
	}
	if _, err := os.Stat(s.path("signatures/400.json")); !os.IsNotExist(err) || s.StandingOf(400) != NotSigned {
		t.Fatal("the record stayed without an event")
	}

	if err := s.Confirm(ctx, 300, pendingDigest(t, s, 300), "admin", time.Now()); err == nil {
		t.Fatal("confirm succeeded without its event")
	}
	if _, err := os.Stat(s.path("signatures/300.json")); !os.IsNotExist(err) || s.StandingOf(300) != Pending {
		t.Fatal("a failed confirm changed the records")
	}

	before, _ := os.ReadFile(s.path("pending/300.json"))
	if err := s.Reject(ctx, 300, pendingDigest(t, s, 300), "admin"); err == nil {
		t.Fatal("reject succeeded without its event")
	}
	if after, _ := os.ReadFile(s.path("pending/300.json")); string(after) != string(before) {
		t.Fatal("a failed reject did not restore the pending record as it was")
	}
}

func TestWritesGiveUpOnAHeldLock(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	if err := s.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	s.wait = 100 * time.Millisecond

	// Held by cla-tool, say.
	unlock, err := audit.Lock(s.dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Create(ctx, Record{GitHubID: 400, Category: Individual}); !errors.Is(err, audit.ErrLockTimeout) {
		t.Fatalf("got %v", err)
	}
	unlock()

	// Held inside the process: the wait for it counts against the same
	// budget, so the two waits never add up.
	s.writeMu.Lock()
	start := time.Now()
	err = s.Refresh(ctx)
	s.writeMu.Unlock()
	if !errors.Is(err, audit.ErrLockTimeout) || time.Since(start) > time.Second {
		t.Fatalf("got %v after %v", err, time.Since(start))
	}
}

func TestAChangeWhoseEventLandedIsKept(t *testing.T) {
	s := newStore(t)
	if err := s.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	path := s.path(RecordPath(SignedDir, 400))
	// The append wrote the event, then reported an error (its sync failed).
	err := Journaled(s.dir, [][]string{{path}}, func() error {
		write(t, s.dir, "signatures/400.json", `{"github_id":400}`)
		if _, err := audit.Append(s.path(AuditLog), audit.Event{Action: audit.Signed, Subject: "x", Actor: "signer", Digest: "d"}); err != nil {
			t.Fatal(err)
		}
		return errors.New("sync failed")
	})
	if _, statErr := os.Stat(path); err != nil || statErr != nil {
		t.Fatalf("a logged change was undone: %v %v", err, statErr)
	}

	path = s.path(RecordPath(SignedDir, 500))
	err = Journaled(s.dir, [][]string{{path}}, func() error {
		write(t, s.dir, "signatures/500.json", `{"github_id":500}`)
		return errors.New("write failed")
	})
	if _, statErr := os.Stat(path); err == nil || !os.IsNotExist(statErr) {
		t.Fatal("an unlogged change was kept")
	}
	if _, statErr := os.Stat(s.path(JournalFile)); !os.IsNotExist(statErr) {
		t.Fatal("the journal was left behind")
	}
}

func TestLogo(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	if err := s.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if data, _, _ := s.Logo(); data != nil {
		t.Fatal("a logo without a file")
	}

	write(t, s.dir, LogoPNG, "png bytes")
	write(t, s.dir, LogoSVG, "<svg/>")
	if err := s.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	data, contentType, version := s.Logo()
	if string(data) != "<svg/>" || contentType != "image/svg+xml" || version == "" {
		t.Fatalf("logo %q %q %q", data, contentType, version)
	}

	// Too large, or a symlink: the letter mark is shown instead.
	if err := os.Remove(s.path(LogoSVG)); err != nil {
		t.Fatal(err)
	}
	write(t, s.dir, LogoPNG, strings.Repeat("x", maxLogo+1))
	if err := s.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if data, _, _ := s.Logo(); data != nil {
		t.Fatal("an oversized logo was used")
	}
	if err := os.Remove(s.path(LogoPNG)); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc/hostname", s.path(LogoSVG)); err != nil {
		t.Fatal(err)
	}
	if err := s.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if data, _, _ := s.Logo(); data != nil {
		t.Fatal("a symlinked logo was followed")
	}
}

func TestAFIFOLogoDoesNotBlock(t *testing.T) {
	s := newStore(t)
	if err := syscall.Mkfifo(s.path(LogoSVG), 0o640); err != nil {
		t.Skip("cannot make a FIFO here:", err)
	}
	done := make(chan error, 1)
	go func() { done <- s.Refresh(context.Background()) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a FIFO logo blocked the refresh")
	}
	if data, _, _ := s.Logo(); data != nil {
		t.Fatal("a FIFO was used as the logo")
	}
}

func TestAConfirmInterruptedBeforeItsEventIsUndone(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	if err := s.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	pending := s.path(RecordPath(PendingDir, 300))
	signed := s.path(RecordPath(SignedDir, 300))
	before, _ := os.ReadFile(pending)
	// Both files changed, as Confirm does before its event, then the
	// process died.
	interrupt(t, s, []string{signed, pending}, func() {
		rec, _ := ReadRecord(pending)
		rec.ConfirmedBy = "admin"
		if _, err := WriteRecord(signed, rec); err != nil {
			t.Fatal(err)
		}
		if err := RemoveRecord(pending); err != nil {
			t.Fatal(err)
		}
	})

	s = New(s.dir)
	if err := s.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if s.StandingOf(300) != Pending {
		t.Fatalf("standing %v", s.StandingOf(300))
	}
	if after, _ := os.ReadFile(pending); string(after) != string(before) {
		t.Fatal("the pending record was not put back as it was")
	}
	if _, err := os.Stat(signed); !os.IsNotExist(err) {
		t.Fatal("the signed record without an event is still there")
	}
}

func TestOnlyChangesWhoseEventsLandedAreKept(t *testing.T) {
	s := newStore(t)
	if err := s.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	paths := []string{s.path(RecordPath(SignedDir, 401)), s.path(RecordPath(SignedDir, 402)), s.path(RecordPath(SignedDir, 403))}
	groups := [][]string{{paths[0]}, {paths[1]}, {paths[2]}}
	err := Journaled(s.dir, groups, func() error {
		for i, p := range paths {
			write(t, s.dir, "signatures/"+filepath.Base(p), fmt.Sprintf(`{"github_id":%d}`, 401+i))
		}
		// Only the first event landed before the append failed.
		if _, err := audit.Append(s.path(AuditLog), audit.Event{Action: audit.Imported, Subject: "x", Actor: "test", Digest: "d"}); err != nil {
			t.Fatal(err)
		}
		return errors.New("append failed")
	})
	if err == nil {
		t.Fatal("a partly applied batch reported success")
	}
	for i, p := range paths {
		_, statErr := os.Stat(p)
		if kept := statErr == nil; kept != (i == 0) {
			t.Fatalf("record %d kept=%v", 401+i, kept)
		}
	}
}

func TestAJournaledWriteRefusesASymlink(t *testing.T) {
	s := newStore(t)
	if err := s.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(secret, []byte("not for the data directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := s.path(RecordPath(SignedDir, 500))
	if err := os.Symlink(secret, path); err != nil {
		t.Fatal(err)
	}
	ran := false
	err := Journaled(s.dir, [][]string{{path}}, func() error { ran = true; return nil })
	if err == nil || ran {
		t.Fatalf("a symlinked record was journaled: %v", err)
	}
	if _, err := os.Stat(s.path(JournalFile)); !os.IsNotExist(err) {
		t.Fatal("a journal was written")
	}
}
