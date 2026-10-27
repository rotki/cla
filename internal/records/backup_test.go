package records

import (
	"archive/tar"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rotki/cla/internal/seal"
	"github.com/rotki/cla/internal/store"
)

// untar extracts an archive into a new directory.
func untar(t *testing.T, path string) string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	dir := t.TempDir()
	tr := tar.NewReader(f)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return dir
		}
		if err != nil {
			t.Fatal(err)
		}
		if strings.HasSuffix(hdr.Name, "/") {
			continue
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		write(t, dir, hdr.Name, string(data))
	}
}

func TestBackupRestoresToTheSameVerifiedState(t *testing.T) {
	k := newKey(t, "2026-01")
	dir := dataDir(t, k)
	write(t, dir, "signatures/100.json.tmp", "half a record")
	out := t.TempDir()
	now := time.Date(2026, 10, 27, 2, 0, 0, 0, time.UTC)

	m, err := Backup(dir, out, now, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !m.OK || m.Archive != "cla-20261027T020000Z.tar" || m.Records != 3 || m.Events != 5 || m.Bytes == 0 {
		t.Fatalf("manifest %+v", m)
	}
	var onDisk Manifest
	data, _ := os.ReadFile(filepath.Join(out, "cla-20261027T020000Z.json"))
	if err := json.Unmarshal(data, &onDisk); err != nil || onDisk.Head != m.Head {
		t.Fatalf("manifest file %s %v", data, err)
	}

	restored := untar(t, filepath.Join(out, m.Archive))
	for _, absent := range []string{".lock", "signatures/100.json.tmp"} {
		if _, err := os.Stat(filepath.Join(restored, absent)); err == nil {
			t.Fatalf("%s was archived", absent)
		}
	}
	report, err := Verify(restored, nil)
	if err != nil || !report.OK() || report.Head != m.Head || report.Records != 3 {
		t.Fatalf("restored copy: %+v %v", report, err)
	}
	if err := CheckAnchor(restored, int64(m.Events), m.Head); err != nil {
		t.Fatal(err)
	}
}

func TestBackupOfABadStateIsMarked(t *testing.T) {
	k := newKey(t, "2026-01")
	dir := dataDir(t, k)
	write(t, dir, "signatures/999.json", `{"github_id":999}`)
	out := t.TempDir()

	m, err := Backup(dir, out, time.Now(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if m.OK || m.Problems == 0 || !strings.HasSuffix(m.Archive, "-unverified.tar") {
		t.Fatalf("manifest %+v", m)
	}
	if _, err := os.Stat(filepath.Join(out, m.Archive)); err != nil {
		t.Fatal("the archive of a bad state was not written")
	}
}

func TestBackupKeepsTheNewest(t *testing.T) {
	k := newKey(t, "2026-01")
	dir := dataDir(t, k)
	out := t.TempDir()
	write(t, out, "notes.txt", "not ours")
	start := time.Date(2026, 10, 1, 2, 0, 0, 0, time.UTC)
	for day := range 4 {
		if _, err := Backup(dir, out, start.AddDate(0, 0, day), 2); err != nil {
			t.Fatal(err)
		}
	}
	entries, _ := os.ReadDir(out)
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	want := "cla-20261003T020000Z.json cla-20261003T020000Z.tar cla-20261004T020000Z.json cla-20261004T020000Z.tar notes.txt"
	if strings.Join(names, " ") != want {
		t.Fatalf("left %v", names)
	}
	latest, ok, err := LatestManifest(out)
	if err != nil || !ok || !latest.Time.Equal(start.AddDate(0, 0, 3)) {
		t.Fatalf("latest %+v %v %v", latest, ok, err)
	}
}

func TestBackupRefusesATargetInsideTheData(t *testing.T) {
	dir := dataDir(t, newKey(t, "2026-01"))
	if _, err := Backup(dir, filepath.Join(dir, "backups"), time.Now(), 0); err == nil {
		t.Fatal("archived the data directory into itself")
	}
}

func TestBackupIsRepeatable(t *testing.T) {
	k := newKey(t, "2026-01")
	dir := dataDir(t, k)
	out := t.TempDir()
	day := time.Date(2026, 10, 1, 2, 0, 0, 0, time.UTC)

	first, err := Backup(dir, out, day, 0)
	if err != nil {
		t.Fatal(err)
	}
	// Times and permissions change on disk, the data does not.
	later := time.Now().Add(time.Hour)
	for _, rel := range []string{"signatures/100.json", "signatures", store.ConfigFile} {
		if err := os.Chtimes(filepath.Join(dir, filepath.FromSlash(rel)), later, later); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(filepath.Join(dir, "signatures", "200.json"), 0o600); err != nil {
		t.Fatal(err)
	}
	second, err := Backup(dir, out, day.AddDate(0, 0, 1), 0)
	if err != nil {
		t.Fatal(err)
	}
	if first.SHA256 == "" || second.SHA256 != first.SHA256 || second.Archive == first.Archive {
		t.Fatalf("unchanged data gave %s then %s", first.SHA256, second.SHA256)
	}
	a, _ := os.ReadFile(filepath.Join(out, first.Archive))
	b, _ := os.ReadFile(filepath.Join(out, second.Archive))
	if string(a) != string(b) {
		t.Fatal("the archives differ byte for byte")
	}

	// Any change to the data changes the hash.
	write(t, dir, store.Grandfathered, `[1, 2, 3, 4]`)
	if err := store.LogFileChanges(dir, "test", day); err != nil {
		t.Fatal(err)
	}
	third, err := Backup(dir, out, day.AddDate(0, 0, 2), 0)
	if err != nil || third.SHA256 == first.SHA256 {
		t.Fatalf("changed data kept the hash: %v", err)
	}
}

func TestBackupClearsWhatAnInterruptedRunLeft(t *testing.T) {
	dir := dataDir(t, newKey(t, "2026-01"))
	out := t.TempDir()
	write(t, out, "cla-20261001T020000Z.tar", "an archive whose manifest was never written")
	write(t, out, "cla-20261002T020000Z.tar.partial", "half an archive")
	write(t, out, "other.tar", "not ours")
	m, err := Backup(dir, out, time.Date(2026, 10, 3, 2, 0, 0, 0, time.UTC), 0)
	if err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(out)
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	if want := "cla-20261003T020000Z.json " + m.Archive + " other.tar"; strings.Join(names, " ") != want {
		t.Fatalf("left %v", names)
	}
}

func TestPruneKeepsTheNewestVerifiedArchive(t *testing.T) {
	out := t.TempDir()
	for _, name := range []string{"cla-20261001T020000Z", "cla-20261002T020000Z", "cla-20261003T020000Z-unverified", "cla-20261004T020000Z-unverified"} {
		write(t, out, name+".tar", "a")
		write(t, out, name+".json", "{}")
	}
	if err := prune(out, 2); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(out)
	var names []string
	for _, e := range entries {
		names = append(names, strings.TrimSuffix(strings.TrimSuffix(e.Name(), ".json"), ".tar"))
	}
	want := "cla-20261002T020000Z cla-20261002T020000Z cla-20261003T020000Z-unverified cla-20261003T020000Z-unverified cla-20261004T020000Z-unverified cla-20261004T020000Z-unverified"
	if strings.Join(names, " ") != want {
		t.Fatalf("kept %v", names)
	}
}

func TestBackupFinishesAnInterruptedChangeFirst(t *testing.T) {
	k := newKey(t, "2026-01")
	dir := dataDir(t, k)
	path := filepath.Join(dir, filepath.FromSlash(store.RecordPath(store.SignedDir, 900)))
	crash(t, dir, []string{path}, func() {
		writeRec(t, dir, store.SignedDir, record(t, k, store.Record{GitHubID: 900, Login: "mallory", Category: store.Individual}, seal.Personal{Name: "M", Email: "m@example.com"}))
	})
	m, err := Backup(dir, t.TempDir(), time.Date(2026, 10, 27, 2, 0, 0, 0, time.UTC), 0)
	if err != nil {
		t.Fatal(err)
	}
	if !m.OK || m.Records != 3 {
		t.Fatalf("manifest %+v", m)
	}
}
