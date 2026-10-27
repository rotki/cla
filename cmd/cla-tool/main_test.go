package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"

	"github.com/rotki/cla/internal/store"
)

// capture runs fn with stdout redirected and returns what it printed.
func capture(t *testing.T, fn func() error) (string, error) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout := os.Stdout
	os.Stdout = w
	runErr := fn()
	os.Stdout = stdout
	_ = w.Close()
	out, _ := io.ReadAll(r)
	return string(out), runErr
}

func key(t *testing.T, dir, name string) (path, recipient string) {
	t.Helper()
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	path = filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(identity.String()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path, identity.Recipient().String()
}

func TestTheMaintenanceCommands(t *testing.T) {
	keys := t.TempDir()
	data := t.TempDir()
	if err := os.WriteFile(filepath.Join(data, store.ConfigFile), []byte(`{"cla_gist":"g","cla_revision":"r1"}`), 0o640); err != nil {
		t.Fatal(err)
	}
	export := filepath.Join(keys, "export.json")
	if err := os.WriteFile(export, []byte(`[
	  {"user":"alice","userId":"100","created_at":"2020-05-01T10:00:00Z","gist_version":"v1",
	   "custom_fields":"{\"name\":\"Alice\",\"email\":\"alice@example.com\"}"},
	  {"user":"bob","userId":"200","created_at":"2021-01-01T10:00:00Z","gist_version":"v1",
	   "custom_fields":"{\"name\":\"Bob\",\"email\":\"bob@example.com\"}"}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	oldKey, oldRecipient := key(t, keys, "old.key")
	newKey, newRecipient := key(t, keys, "new.key")

	if err := importExport([]string{"-export", export, "-recipient", oldRecipient, "-key-id", "2026-01", "-dir", data}); err != nil {
		t.Fatal(err)
	}
	// The import wrote no settings event: hand-copied config.json is logged
	// by the service's next refresh, which this stands in for.
	if err := store.New(data).Refresh(t.Context()); err != nil {
		t.Fatal(err)
	}

	out, err := capture(t, func() error { return verify([]string{"-dir", data, "-identity", oldKey}) })
	if err != nil || !strings.Contains(out, "2 records") || !strings.Contains(out, "2 decrypted") {
		t.Fatalf("verify: %v\n%s", err, out)
	}
	var events int
	var head string
	for line := range strings.SplitSeq(out, "\n") {
		if rest, ok := strings.CutPrefix(line, "audit log: "); ok {
			_, _ = fmt.Sscanf(rest, "%d events, head %s", &events, &head)
		}
	}
	anchor := fmt.Sprintf("%d:%s", events, head)
	if out, err := capture(t, func() error { return verify([]string{"-dir", data, "-anchor", anchor}) }); err != nil || !strings.Contains(out, "matches the anchor") {
		t.Fatalf("verify -anchor %s: %v\n%s", anchor, err, out)
	}
	if _, err := capture(t, func() error {
		return verify([]string{"-dir", data, "-anchor", fmt.Sprintf("%d:%s", events, strings.Repeat("0", 64))})
	}); err == nil {
		t.Fatal("a wrong anchor passed")
	}

	out, err = capture(t, func() error {
		return decrypt([]string{"-identity", oldKey, filepath.Join(data, "signatures", "100.json")})
	})
	if err != nil || !strings.Contains(out, "alice@example.com") {
		t.Fatalf("decrypt: %v\n%s", err, out)
	}

	if _, err := capture(t, func() error {
		return rekey([]string{"-dir", data, "-identity", oldKey, "-recipient", newRecipient, "-key-id", "2027-01"})
	}); err != nil {
		t.Fatal(err)
	}
	if out, err := capture(t, func() error { return verify([]string{"-dir", data, "-identity", newKey}) }); err != nil || !strings.Contains(out, "2 decrypted") {
		t.Fatalf("verify after rekey: %v\n%s", err, out)
	}

	backups := t.TempDir()
	out, err = capture(t, func() error { return backup([]string{"-dir", data, "-o", backups, "-keep", "1"}) })
	if err != nil {
		t.Fatalf("backup: %v\n%s", err, out)
	}
	var manifest struct {
		OK      bool `json:"ok"`
		Records int  `json:"records"`
	}
	if err := json.Unmarshal([]byte(out), &manifest); err != nil || !manifest.OK || manifest.Records != 2 {
		t.Fatalf("manifest %s %v", out, err)
	}

	for name, run := range map[string]func() error{
		"backup without -o":   func() error { return backup([]string{"-dir", data}) },
		"rekey without keys":  func() error { return rekey([]string{"-dir", data}) },
		"import without args": func() error { return importExport(nil) },
		"decrypt without key": func() error { return decrypt(nil) },
	} {
		if _, err := capture(t, run); err == nil {
			t.Errorf("%s succeeded", name)
		}
	}
}

func TestWriteNewReplacesASymlinkInsteadOfFollowingIt(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "elsewhere")
	if err := os.WriteFile(target, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "grandfathered.json")
	if err := os.Symlink(target, out); err != nil {
		t.Fatal(err)
	}
	if err := writeNew(out, []byte("[1]\n")); err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(target); string(data) != "keep" {
		t.Fatal("the write went through the symlink")
	}
	if info, err := os.Lstat(out); err != nil || !info.Mode().IsRegular() {
		t.Fatalf("output is not a regular file: %v", err)
	}
}
