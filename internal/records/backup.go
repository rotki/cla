package records

import (
	"archive/tar"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/rotki/cla/internal/audit"
	"github.com/rotki/cla/internal/store"
)

// Manifest describes one archive. It is written next to the archive after
// it, so a manifest means the archive is complete. It holds counts and
// hashes only, never personal data.
type Manifest struct {
	Time    time.Time `json:"time"`
	Archive string    `json:"archive"`
	Bytes   int64     `json:"bytes"`
	// SHA256 is the archive's hash. The archive depends only on the files'
	// names and contents, so an unchanged directory gives the same hash and
	// a backup job can skip uploading it again.
	SHA256        string `json:"sha256"`
	OK            bool   `json:"ok"`
	Problems      int    `json:"problems"`
	Records       int    `json:"records"`
	Grandfathered int    `json:"grandfathered"`
	Events        int    `json:"events"`
	Head          string `json:"head"`
}

// archivePrefix starts every file Backup writes; Backup prunes nothing else.
const archivePrefix = "cla-"

// Backup verifies the data directory dir and writes it as a tar archive
// into outDir, holding the writers' lock throughout, so the archive is
// exactly the state that was verified. It is written even when verification
// finds problems, so the copy of a bad state is kept for investigation and
// the older good backups are not crowded out; its name then ends in
// "-unverified" and the manifest says ok: false.
//
// Files are written as .partial and renamed once synced; the manifest,
// cla-<time>.json, comes last. keep > 0 removes all but the newest keep
// archives from outDir.
func Backup(dir, outDir string, now time.Time, keep int) (Manifest, error) {
	m := Manifest{Time: now.UTC().Truncate(time.Second)}
	if inside(outDir, dir) {
		return m, errors.New("the backup directory must be outside the data directory")
	}
	if err := os.MkdirAll(outDir, 0o750); err != nil {
		return m, err
	}

	unlock, err := audit.Lock(dir)
	if err != nil {
		return m, err
	}
	defer unlock()
	if _, err := store.RecoverJournal(dir); err != nil {
		return m, err
	}

	report, err := verify(dir, nil)
	if err != nil {
		return m, err
	}
	m.OK, m.Problems = report.OK(), len(report.Problems)
	m.Records, m.Grandfathered, m.Events, m.Head = report.Records, report.Grandfathered, report.Events, report.Head

	name := archivePrefix + m.Time.Format("20060102T150405Z")
	if !m.OK {
		name += "-unverified"
	}
	m.Archive = name + ".tar"
	hash := sha256.New()
	if m.Bytes, err = writeAtomically(filepath.Join(outDir, m.Archive), func(w io.Writer) error {
		return writeTar(io.MultiWriter(w, hash), dir)
	}); err != nil {
		return m, err
	}
	m.SHA256 = hex.EncodeToString(hash.Sum(nil))
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return m, err
	}
	if _, err := writeAtomically(filepath.Join(outDir, name+".json"), func(w io.Writer) error {
		_, err := w.Write(append(data, '\n'))
		return err
	}); err != nil {
		return m, err
	}
	return m, prune(outDir, keep)
}

// inside reports whether path is dir or below it.
func inside(path, dir string) bool {
	p, err1 := filepath.Abs(path)
	d, err2 := filepath.Abs(dir)
	if err1 != nil || err2 != nil {
		return false
	}
	rel, err := filepath.Rel(d, p)
	return err == nil && (rel == "." || !strings.HasPrefix(rel, ".."))
}

// writeTar adds every file of the data directory except the lock and
// temporary files. The output is repeatable: entries come in name order and
// carry only a name, a fixed mode, a size and the contents, never times,
// owners or permissions as found on disk, so the same data always gives the
// same bytes.
func writeTar(w io.Writer, dir string) error {
	tw := tar.NewWriter(w)
	buf := make([]byte, 32<<10)
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil || rel == "." {
			return err
		}
		if d.Name() == ".lock" || strings.HasSuffix(d.Name(), ".tmp") {
			return nil
		}
		if !d.IsDir() && !d.Type().IsRegular() {
			return nil
		}
		hdr := &tar.Header{
			Name:    filepath.ToSlash(rel),
			ModTime: time.Unix(0, 0),
			Format:  tar.FormatPAX,
		}
		if d.IsDir() {
			hdr.Name += "/"
			hdr.Typeflag, hdr.Mode = tar.TypeDir, 0o750
			return tw.WriteHeader(hdr)
		}
		// Opened without following a link and without blocking, and checked
		// after opening, so a file swapped for a symlink or a FIFO since the
		// walk saw it is never read and never stalls the backup.
		f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
		if err != nil {
			return err
		}
		defer func() { _ = f.Close() }()
		info, err := f.Stat()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("%s is no longer a regular file", rel)
		}
		hdr.Typeflag, hdr.Mode, hdr.Size = tar.TypeReg, 0o640, info.Size()
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		// One buffer for every file; the plain reader stops io.CopyBuffer
		// from taking the file's own path, which allocates per call.
		_, err = io.CopyBuffer(tw, struct{ io.Reader }{f}, buf)
		return err
	})
	if err != nil {
		return err
	}
	return tw.Close()
}

// writeAtomically writes path through path.partial, synced and renamed, and
// returns the size written.
func writeAtomically(path string, write func(io.Writer) error) (int64, error) {
	partial := path + ".partial"
	if err := os.Remove(partial); err != nil && !errors.Is(err, os.ErrNotExist) {
		return 0, err
	}
	f, err := os.OpenFile(partial, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o640)
	if err != nil {
		return 0, err
	}
	fail := func(err error) (int64, error) {
		_ = f.Close()
		_ = os.Remove(partial)
		return 0, err
	}
	if err := write(f); err != nil {
		return fail(err)
	}
	if err := f.Sync(); err != nil {
		return fail(err)
	}
	info, err := f.Stat()
	if err != nil {
		return fail(err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(partial)
		return 0, err
	}
	if err := os.Rename(partial, path); err != nil {
		return 0, err
	}
	d, err := os.Open(filepath.Dir(path))
	if err != nil {
		return 0, err
	}
	defer func() { _ = d.Close() }()
	return info.Size(), d.Sync()
}

// prune removes what an interrupted run left behind: .partial files and
// archives without a manifest. With keep > 0 it also keeps only the newest
// keep archives and their manifests. Names sort by time, so the newest sort
// last. Only files named cla-* are ever touched. The caller holds the data
// lock, which every writer of outDir takes, so nothing here is in progress.
func prune(outDir string, keep int) error {
	entries, err := os.ReadDir(outDir)
	if err != nil {
		return err
	}
	manifests := map[string]bool{}
	var names, remove []string
	for _, e := range entries {
		n := e.Name()
		if !strings.HasPrefix(n, archivePrefix) || e.IsDir() {
			continue
		}
		if name, ok := strings.CutSuffix(n, ".json"); ok {
			manifests[name] = true
			names = append(names, name)
		}
	}
	for _, e := range entries {
		n := e.Name()
		if !strings.HasPrefix(n, archivePrefix) || e.IsDir() {
			continue
		}
		if strings.HasSuffix(n, ".partial") {
			remove = append(remove, n)
		} else if name, ok := strings.CutSuffix(n, ".tar"); ok && !manifests[name] {
			remove = append(remove, n)
		}
	}
	if keep > 0 {
		slices.Sort(names)
		// The newest verified archive is always kept, even when newer
		// unverified ones would push it out: days of failed checks must not
		// leave only copies of a bad state.
		newestVerified := ""
		for _, name := range names {
			if !strings.HasSuffix(name, "-unverified") {
				newestVerified = name
			}
		}
		for _, name := range names[:max(len(names)-keep, 0)] {
			if name != newestVerified {
				remove = append(remove, name+".tar", name+".json")
			}
		}
	}
	for _, n := range remove {
		if err := os.Remove(filepath.Join(outDir, n)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

// LatestManifest returns the newest manifest in outDir, and false when
// there is none.
func LatestManifest(outDir string) (Manifest, bool, error) {
	entries, err := os.ReadDir(outDir)
	if errors.Is(err, os.ErrNotExist) {
		return Manifest{}, false, nil
	}
	if err != nil {
		return Manifest{}, false, err
	}
	latest := ""
	for _, e := range entries {
		if n := e.Name(); strings.HasPrefix(n, archivePrefix) && strings.HasSuffix(n, ".json") && n > latest {
			latest = n
		}
	}
	if latest == "" {
		return Manifest{}, false, nil
	}
	data, err := os.ReadFile(filepath.Join(outDir, latest))
	if err != nil {
		return Manifest{}, false, err
	}
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return Manifest{}, false, fmt.Errorf("%s: %w", latest, err)
	}
	return m, true, nil
}
