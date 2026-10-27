package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rotki/cla/internal/alert"
	"github.com/rotki/cla/internal/audit"
	"github.com/rotki/cla/internal/records"
	"github.com/rotki/cla/internal/store"
)

// discord records what is posted to a fake Discord webhook.
type discord struct {
	mu       sync.Mutex
	messages []string
	fail     bool
}

func (d *discord) serve(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		d.mu.Lock()
		defer d.mu.Unlock()
		if d.fail {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		d.messages = append(d.messages, string(body))
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func (d *discord) waitFor(t *testing.T, text string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		d.mu.Lock()
		for _, m := range d.messages {
			if strings.Contains(m, text) {
				d.mu.Unlock()
				return
			}
		}
		d.mu.Unlock()
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("no message with %q; got %v", text, d.messages)
}

func dataDir(t *testing.T) *store.Store {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, store.ConfigFile), []byte(`{"cla_gist":"g","cla_revision":"r1"}`), 0o640); err != nil {
		t.Fatal(err)
	}
	st := store.New(dir)
	if err := st.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	return st
}

func TestAnchorPublishesTheVerifiedHead(t *testing.T) {
	st := dataDir(t)
	d := &discord{}
	alerts := alert.New(d.serve(t))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go alerts.Run(ctx)
	go anchor(ctx, st, alerts, time.Hour, "")
	d.waitFor(t, "Audit log anchor** seq 1 `"+st.Head()+"`")
}

func TestAnchorRefusesABrokenChain(t *testing.T) {
	st := dataDir(t)
	logPath := filepath.Join(st.Dir(), filepath.FromSlash(store.AuditLog))
	data, _ := os.ReadFile(logPath)
	if err := os.WriteFile(logPath, []byte(strings.Replace(string(data), `"actor":"service"`, `"actor":"admin:x"`, 1)), 0o640); err != nil {
		t.Fatal(err)
	}
	d := &discord{}
	alerts := alert.New(d.serve(t))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go alerts.Run(ctx)
	go anchor(ctx, st, alerts, time.Hour, "")
	d.waitFor(t, "audit log chain is broken")
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, m := range d.messages {
		if strings.Contains(m, "anchor** seq") {
			t.Fatal("published the head of a broken chain")
		}
	}
}

func TestBackupsWriteOnStartAndNotAgainAfterARestart(t *testing.T) {
	st := dataDir(t)
	out := t.TempDir()
	alerts := alert.New("")
	ctx, cancel := context.WithCancel(context.Background())
	go backups(ctx, st.Dir(), out, time.Hour, 2, alerts)
	deadline := time.Now().Add(5 * time.Second)
	for {
		if m, ok, _ := records.LatestManifest(out); ok && m.OK {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no backup on start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()

	// A restart within the interval finds the archive and waits.
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	go backups(ctx, st.Dir(), out, time.Hour, 2, alerts)
	time.Sleep(200 * time.Millisecond)
	entries, _ := os.ReadDir(out)
	if len(entries) != 2 {
		t.Fatalf("a restart added a backup: %d files", len(entries))
	}
}

func TestBackupsAlertWhenTheDataFailsVerification(t *testing.T) {
	st := dataDir(t)
	if err := os.MkdirAll(filepath.Join(st.Dir(), "signatures"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(st.Dir(), "signatures", "9.json"), []byte(`{"github_id":9}`), 0o640); err != nil {
		t.Fatal(err)
	}
	d := &discord{}
	alerts := alert.New(d.serve(t))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go alerts.Run(ctx)
	go backups(ctx, st.Dir(), t.TempDir(), time.Hour, 2, alerts)
	d.waitFor(t, "failed verification")
}

func TestBackupsAlertWhenTheyCannotBeWritten(t *testing.T) {
	st := dataDir(t)
	d := &discord{}
	alerts := alert.New(d.serve(t))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go alerts.Run(ctx)
	// Inside the data directory, which Backup refuses.
	go backups(ctx, st.Dir(), filepath.Join(st.Dir(), "backups"), time.Hour, 2, alerts)
	d.waitFor(t, "failed or was skipped")
}

func TestAnchorNoticesALogCutBackSinceTheLastBackup(t *testing.T) {
	st := dataDir(t)
	backups := t.TempDir()
	if _, err := records.Backup(st.Dir(), backups, time.Now(), 0); err != nil {
		t.Fatal(err)
	}
	// The log is replaced by a shorter, consistent one.
	logPath := filepath.Join(st.Dir(), filepath.FromSlash(store.AuditLog))
	if err := os.Remove(logPath); err != nil {
		t.Fatal(err)
	}
	if _, err := audit.Append(logPath, audit.Event{Action: audit.Config, Actor: "service", Digest: "forged"}); err != nil {
		t.Fatal(err)
	}
	d := &discord{}
	alerts := alert.New(d.serve(t))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go alerts.Run(ctx)
	go anchor(ctx, st, alerts, time.Hour, backups)
	d.waitFor(t, "audit log chain is broken")
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, m := range d.messages {
		if strings.Contains(m, "anchor** seq") {
			t.Fatal("anchored a log that lost the backed-up head")
		}
	}
}
