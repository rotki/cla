// Package audit keeps the append-only, hash-chained log of every change to
// the signature records.
//
// Each line of the log is one JSON event that carries the hash of the line
// before it, so editing or removing any line breaks every hash after it.
// Events never hold names, emails or account IDs: the subject is an HMAC of
// the account ID under a random salt kept in the account's record, so the
// log can be anchored and backed up without saying who signed; only someone
// holding the records can tell which events are whose.
//
// The log is only ever appended to, so it works with chattr +a. Writers hold
// Lock while they change records and append, which keeps the server and
// cla-tool from forking the chain.
package audit

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
)

// Actions recorded in the log.
const (
	Signed        = "signed"
	Pending       = "pending"
	Confirmed     = "confirmed"
	Rejected      = "rejected"
	Rekeyed       = "rekeyed"
	Imported      = "imported"
	Config        = "config"
	Grandfathered = "grandfathered"
)

// Event is one line of the log.
type Event struct {
	Seq    int64     `json:"seq"`
	Time   time.Time `json:"time"`
	Action string    `json:"action"`
	// Subject is the account's pseudonym, see Subject; empty for file events.
	Subject string `json:"subject,omitempty"`
	// Actor is "signer", "admin:<login>", "service" or "cla-tool".
	Actor string `json:"actor"`
	// Digest is the SHA-256 of the file as it stands after the change,
	// empty when the change removed it.
	Digest string `json:"digest,omitempty"`
	Prev   string `json:"prev"`
	Hash   string `json:"hash"`
}

// hash is the SHA-256 of the event's JSON with the hash field left empty.
func (e Event) hash() (string, error) {
	e.Hash = ""
	data, err := json.Marshal(e)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

// NewSalt returns a random salt for a new record.
func NewSalt() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// Subject is the pseudonym of an account in the log.
func Subject(salt string, id int64) string {
	mac := hmac.New(sha256.New, []byte(salt))
	mac.Write([]byte(strconv.FormatInt(id, 10)))
	return hex.EncodeToString(mac.Sum(nil))[:32]
}

// Digest is the SHA-256 of a file's contents.
func Digest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// LockTimeout is how long a writer waits for the lock by default. Holders
// keep it for well under a second: long jobs such as a rekey work in
// batches and let go in between. A stuck holder makes writers fail with
// ErrLockTimeout instead of hanging.
const LockTimeout = 20 * time.Second

// ErrLockTimeout is returned when the lock stays taken past the deadline.
var ErrLockTimeout = errors.New("timed out waiting for the data directory lock")

// Lock takes the exclusive lock on dir that every writer holds, waiting at
// most LockTimeout; call the returned function to release it.
func Lock(dir string) (func(), error) {
	return LockUntil(dir, time.Now().Add(LockTimeout))
}

// LockUntil is Lock with an explicit deadline, for callers that also wait
// on something else and must stay within one budget.
func LockUntil(dir string, deadline time.Time) (func(), error) {
	// O_NOFOLLOW everywhere in the data directory: whoever runs as the
	// directory's owner (the service user) could plant symlinks there.
	f, err := os.OpenFile(filepath.Join(dir, ".lock"), os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	for {
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			break
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) {
			_ = f.Close()
			return nil, err
		}
		if time.Now().After(deadline) {
			_ = f.Close()
			return nil, ErrLockTimeout
		}
		time.Sleep(20 * time.Millisecond)
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
	}, nil
}

// maxLine bounds one event; real ones are a few hundred bytes. maxScan
// bounds any line the scanner accepts, torn fragments and junk included.
const (
	maxLine = 4 << 10
	maxScan = 64 << 10
)

// Last returns the newest event, and false when the log is empty or absent.
// A torn final line, left by a write that failed halfway, is skipped.
func Last(path string) (Event, bool, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return Event{}, false, nil
	}
	if err != nil {
		return Event{}, false, err
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return Event{}, false, err
	}
	size := info.Size()
	start := max(size-2*maxLine, 0)
	buf := make([]byte, size-start)
	if _, err := f.ReadAt(buf, start); err != nil && !errors.Is(err, io.EOF) {
		return Event{}, false, err
	}
	lines := bytes.Split(buf, []byte("\n"))
	if start > 0 {
		// The window may begin inside a line.
		lines = lines[1:]
	}
	for i := len(lines) - 1; i >= 0; i-- {
		var e Event
		if len(lines[i]) > 0 && json.Unmarshal(lines[i], &e) == nil && e.Hash != "" {
			return e, true, nil
		}
	}
	if start > 0 {
		return Event{}, false, fmt.Errorf("no event in the last %d bytes of %s parses", 2*maxLine, filepath.Base(path))
	}
	return Event{}, false, nil
}

// subjectTime is how precisely an account's events are dated. A day, not a
// millisecond: a signing re-checks the contributor's pull request at once,
// and an exact time would match that public status change, which would tell
// from the log alone whose event it is.
const subjectTime = 24 * time.Hour

// Append chains e onto the log at path and writes it durably. See AppendAll.
func Append(path string, e Event) (Event, error) {
	events, err := AppendAll(path, []Event{e})
	if len(events) == 1 {
		e = events[0]
	}
	return e, err
}

// AppendAll chains events onto the log at path in one write and one sync.
// Seq, Prev and Hash are filled in; Time is set when empty. If the log ends
// in a torn line, the new events start on a line of their own, and the torn
// one stays behind as a fragment that Scan reports. The caller holds Lock.
func AppendAll(path string, events []Event) ([]Event, error) {
	if len(events) == 0 {
		return nil, nil
	}
	last, ok, err := Last(path)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	torn, err := endsTorn(path)
	if err != nil {
		return nil, err
	}
	if torn {
		buf.WriteByte('\n')
	}
	out := make([]Event, len(events))
	for i, e := range events {
		e.Seq, e.Prev = 1, ""
		if ok {
			e.Seq, e.Prev = last.Seq+1, last.Hash
		}
		if e.Time.IsZero() {
			e.Time = time.Now()
		}
		e.Time = e.Time.UTC().Truncate(time.Millisecond)
		if e.Subject != "" {
			e.Time = e.Time.Truncate(subjectTime)
		}
		if e.Hash, err = e.hash(); err != nil {
			return nil, err
		}
		line, err := json.Marshal(e)
		if err != nil {
			return nil, err
		}
		buf.Write(line)
		buf.WriteByte('\n')
		out[i], last, ok = e, e, true
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE|syscall.O_NOFOLLOW, 0o640)
	if err != nil {
		return nil, err
	}
	// From here on the events are returned with the error: a failed sync
	// or close may still have left them in the log, and the caller asks
	// Written before undoing anything.
	if _, err := f.Write(buf.Bytes()); err != nil {
		_ = f.Close()
		return out, err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return out, err
	}
	return out, f.Close()
}

// Written reports how many of events, as returned by a failed AppendAll,
// made it into the log: an append can fail after its lines were written,
// and undoing a change whose event is in the log would leave an event no
// record matches. The caller holds Lock.
func Written(path string, events []Event) (int, error) {
	if len(events) == 0 {
		return 0, nil
	}
	last, ok, err := Last(path)
	if err != nil || !ok {
		return 0, err
	}
	for i := len(events) - 1; i >= 0; i-- {
		if events[i].Seq == last.Seq && events[i].Hash == last.Hash {
			return i + 1, nil
		}
	}
	return 0, nil
}

// endsTorn reports whether the log's last byte is not a newline.
func endsTorn(path string) (bool, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil || info.Size() == 0 {
		return false, err
	}
	b := make([]byte, 1)
	if _, err := f.ReadAt(b, info.Size()-1); err != nil {
		return false, err
	}
	return b[0] != '\n', nil
}

// Chain is how far a scan got: the events read, the newest hash, and the
// offset just past the last whole line, from which a later scan can resume.
type Chain struct {
	Events int64
	Head   string
	Size   int64
	// Fragments are the line numbers of lines that are not events: torn
	// writes. They hold nothing the chain depends on, so they are reported,
	// not treated as a break.
	Fragments []int64
	// TornTail is set when the log ends in a fragment without a newline: a
	// write that failed halfway. The next append starts after it.
	TornTail bool
	lines    int64
}

// Scan reads the whole log and checks its chain: the sequence has no gaps,
// each event names the hash of the one before and its own hash matches its
// content. fn, when not nil, sees every event in order. It returns the chain
// up to the first break and an error describing the break.
func Scan(path string, fn func(Event) error) (Chain, error) {
	return ScanFrom(path, Chain{}, fn)
}

// ScanFrom continues a scan where an earlier one ended, checking only what
// was appended since. A log shorter than before was truncated.
func ScanFrom(path string, from Chain, fn func(Event) error) (Chain, error) {
	c := from
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		if from.Size > 0 {
			return c, errors.New("the log is gone")
		}
		return c, nil
	}
	if err != nil {
		return c, err
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return c, err
	}
	if info.Size() < from.Size {
		return c, fmt.Errorf("the log shrank from %d to %d bytes: it was truncated", from.Size, info.Size())
	}
	if _, err := f.Seek(from.Size, io.SeekStart); err != nil {
		return c, err
	}

	reader := bufio.NewReaderSize(f, maxLine)
	for {
		line, err := readLine(reader)
		if errors.Is(err, io.EOF) && len(line) == 0 {
			return c, nil
		}
		if err != nil && !errors.Is(err, io.EOF) {
			return c, err
		}
		whole := !errors.Is(err, io.EOF)
		content := bytes.TrimSuffix(line, []byte("\n"))
		var e Event
		parsed := len(content) > 0 && json.Unmarshal(content, &e) == nil
		if !whole && !parsed {
			// Torn: left out of the resume point, so it is read again,
			// whole, once an append has ended it with a newline.
			c.TornTail = true
			return c, nil
		}
		c.TornTail = false
		c.lines++
		c.Size += int64(len(line))
		switch {
		case len(content) == 0:
			// The newline an append adds after a torn line that turned out
			// to be a whole event.
		case !parsed:
			c.Fragments = append(c.Fragments, c.lines)
		default:
			n := c.Events + 1
			if e.Seq != n {
				return c, fmt.Errorf("line %d has seq %d, expected %d", c.lines, e.Seq, n)
			}
			if e.Prev != c.Head {
				return c, fmt.Errorf("line %d does not follow the event before it: the log was edited", c.lines)
			}
			if want, err := e.hash(); err != nil || want != e.Hash {
				return c, fmt.Errorf("line %d does not match its hash: the log was edited", c.lines)
			}
			if fn != nil {
				if err := fn(e); err != nil {
					return c, err
				}
			}
			c.Events, c.Head = n, e.Hash
		}
		if !whole {
			return c, nil
		}
	}
}

// readLine reads up to and including the next newline, refusing lines
// longer than maxScan.
func readLine(r *bufio.Reader) ([]byte, error) {
	var line []byte
	for {
		chunk, err := r.ReadSlice('\n')
		line = append(line, chunk...)
		if len(line) > maxScan {
			return nil, fmt.Errorf("a line is longer than %d bytes", maxScan)
		}
		if !errors.Is(err, bufio.ErrBufferFull) {
			return line, err
		}
	}
}

// Read returns every event of the log, checking the chain as Scan does.
func Read(path string) ([]Event, error) {
	var events []Event
	_, err := Scan(path, func(e Event) error {
		events = append(events, e)
		return nil
	})
	return events, err
}
