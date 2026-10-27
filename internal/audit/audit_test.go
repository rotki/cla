package audit

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func appendN(t *testing.T, path string, n int) {
	t.Helper()
	for range n {
		if _, err := Append(path, Event{Action: Signed, Subject: "s", Actor: "signer", Digest: "d"}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestChain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit", "events.jsonl")
	if _, ok, err := Last(path); ok || err != nil {
		t.Fatalf("an absent log: %v %v", ok, err)
	}
	appendN(t, path, 3)

	events, err := Read(path)
	if err != nil || len(events) != 3 {
		t.Fatalf("%d events, %v", len(events), err)
	}
	if events[0].Prev != "" || events[1].Prev != events[0].Hash || events[2].Prev != events[1].Hash {
		t.Fatal("the events are not chained")
	}
	if last, ok, _ := Last(path); !ok || last.Hash != events[2].Hash || last.Seq != 3 {
		t.Fatalf("last %+v", last)
	}
}

func TestReadFindsEdits(t *testing.T) {
	cases := map[string]func(lines []string) []string{
		"edited": func(l []string) []string {
			l[1] = strings.Replace(l[1], `"actor":"signer"`, `"actor":"admin:x"`, 1)
			return l
		},
		"removed":   func(l []string) []string { return append(l[:1], l[2:]...) },
		"reordered": func(l []string) []string { l[0], l[1] = l[1], l[0]; return l },
		"garbage":   func(l []string) []string { l[1] = "not json"; return l },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "events.jsonl")
			appendN(t, path, 3)
			data, _ := os.ReadFile(path)
			lines := strings.Split(strings.TrimSpace(string(data)), "\n")
			if err := os.WriteFile(path, []byte(strings.Join(mutate(lines), "\n")+"\n"), 0o640); err != nil {
				t.Fatal(err)
			}
			if _, err := Read(path); err == nil {
				t.Fatal("the change went unnoticed")
			}
		})
	}
}

func TestRewritingTheWholeChainChangesItsHashes(t *testing.T) {
	// A consistent forgery is possible, which is why the head is anchored
	// outside: the forged hashes differ from the published ones.
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")
	appendN(t, path, 2)
	original, _ := Read(path)

	forged := filepath.Join(dir, "forged.jsonl")
	if _, err := Append(forged, Event{Action: Signed, Subject: "s", Actor: "signer", Digest: "d"}); err != nil {
		t.Fatal(err)
	}
	if _, err := Append(forged, Event{Action: Rekeyed, Subject: "s", Actor: "cla-tool"}); err != nil {
		t.Fatal(err)
	}
	rewritten, err := Read(forged)
	if err != nil {
		t.Fatal(err)
	}
	if rewritten[1].Hash == original[1].Hash {
		t.Fatal("a different history has the same head")
	}
}

func TestSubject(t *testing.T) {
	a, b := Subject("salt1", 42), Subject("salt2", 42)
	if a == b || a != Subject("salt1", 42) || len(a) != 32 || strings.Contains(a, "42") {
		t.Fatalf("subjects %q %q", a, b)
	}
}

func TestLockSerialisesAppends(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			unlock, err := Lock(dir)
			if err != nil {
				t.Error(err)
				return
			}
			defer unlock()
			appendN(t, path, 5)
		})
	}
	wg.Wait()
	if events, err := Read(path); err != nil || len(events) != 40 {
		t.Fatalf("%d events, %v", len(events), err)
	}
}

func TestLockTimesOut(t *testing.T) {
	dir := t.TempDir()
	unlock, err := Lock(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	if _, err := LockUntil(dir, time.Now().Add(50*time.Millisecond)); !errors.Is(err, ErrLockTimeout) {
		t.Fatalf("got %v", err)
	}
}

func TestATornWriteDoesNotBlockTheLog(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	appendN(t, path, 2)
	// A write that stopped halfway, as after a full disk or a power cut.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString(`{"seq":3,"time":"2026-`)
	_ = f.Close()

	chain, err := Scan(path, nil)
	if err != nil || chain.Events != 2 || !chain.TornTail {
		t.Fatalf("torn log: %+v %v", chain, err)
	}
	if last, ok, err := Last(path); err != nil || !ok || last.Seq != 2 {
		t.Fatalf("last %+v %v %v", last, ok, err)
	}

	appendN(t, path, 1)
	chain, err = Scan(path, nil)
	if err != nil || chain.Events != 3 || chain.TornTail || len(chain.Fragments) != 1 || chain.Fragments[0] != 3 {
		t.Fatalf("after the next append: %+v %v", chain, err)
	}
}

func TestAWholeEventMissingOnlyItsNewline(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	appendN(t, path, 2)
	data, _ := os.ReadFile(path)
	if err := os.WriteFile(path, data[:len(data)-1], 0o640); err != nil {
		t.Fatal(err)
	}
	mid, err := Scan(path, nil)
	if err != nil || mid.Events != 2 {
		t.Fatalf("%+v %v", mid, err)
	}
	appendN(t, path, 1)
	if chain, err := ScanFrom(path, mid, nil); err != nil || chain.Events != 3 || len(chain.Fragments) != 0 {
		t.Fatalf("resumed: %+v %v", chain, err)
	}
	if chain, err := Scan(path, nil); err != nil || chain.Events != 3 {
		t.Fatalf("full: %+v %v", chain, err)
	}
}

func TestScanFromChecksOnlyWhatIsNew(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	appendN(t, path, 3)
	first, err := Scan(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	appendN(t, path, 2)
	seen := 0
	next, err := ScanFrom(path, first, func(Event) error { seen++; return nil })
	if err != nil || seen != 2 || next.Events != 5 {
		t.Fatalf("resumed scan saw %d: %+v %v", seen, next, err)
	}

	data, _ := os.ReadFile(path)
	if err := os.WriteFile(path, data[:first.Size], 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := ScanFrom(path, next, nil); err == nil || !strings.Contains(err.Error(), "truncated") {
		t.Fatalf("a truncated log: %v", err)
	}
}

func TestAccountEventsAreDatedToTheDay(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	at := time.Date(2026, 10, 27, 14, 3, 7, 0, time.UTC)
	signed, err := Append(path, Event{Time: at, Action: Signed, Subject: "s", Actor: "signer"})
	if err != nil {
		t.Fatal(err)
	}
	config, err := Append(path, Event{Time: at, Action: Config, Actor: "service"})
	if err != nil {
		t.Fatal(err)
	}
	if !signed.Time.Equal(time.Date(2026, 10, 27, 0, 0, 0, 0, time.UTC)) || !config.Time.Equal(at) {
		t.Fatalf("times %v %v", signed.Time, config.Time)
	}
}

func TestWrittenCountsWhatLanded(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	appendN(t, path, 1)
	events, err := AppendAll(path, []Event{{Action: Signed, Subject: "a", Actor: "signer"}, {Action: Signed, Subject: "b", Actor: "signer"}})
	if err != nil {
		t.Fatal(err)
	}
	if n, err := Written(path, events); err != nil || n != 2 {
		t.Fatalf("written %d, %v", n, err)
	}
	if n, _ := Written(path, events[:1]); n != 0 {
		t.Fatalf("an event not last in the log counted as the last written: %d", n)
	}
	other := []Event{{Seq: 3, Hash: "not this one"}}
	if n, _ := Written(path, other); n != 0 {
		t.Fatalf("a foreign event counted: %d", n)
	}
}
