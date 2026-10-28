package web

import (
	"context"
	"log"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rotki/cla/internal/check"
	"github.com/rotki/cla/internal/fakegh"
)

// alertLog collects the alert messages the notifier logs; without a webhook
// that is where they go.
type alertLog struct {
	mu       sync.Mutex
	messages []string
}

func (l *alertLog) Enabled(context.Context, slog.Level) bool { return true }
func (l *alertLog) WithAttrs([]slog.Attr) slog.Handler       { return l }
func (l *alertLog) WithGroup(string) slog.Handler            { return l }

func (l *alertLog) Handle(_ context.Context, r slog.Record) error {
	if r.Message != "alert" {
		return nil
	}
	r.Attrs(func(a slog.Attr) bool {
		if a.Key == "message" {
			l.mu.Lock()
			l.messages = append(l.messages, a.Value.String())
			l.mu.Unlock()
		}
		return true
	})
	return nil
}

func (l *alertLog) has(text string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, m := range l.messages {
		if strings.Contains(m, text) {
			return true
		}
	}
	return false
}

func captureAlerts(t *testing.T) *alertLog {
	t.Helper()
	logs := &alertLog{}
	prev, prevOut, prevFlags := slog.Default(), log.Writer(), log.Flags()
	slog.SetDefault(slog.New(logs))
	t.Cleanup(func() {
		slog.SetDefault(prev)
		log.SetOutput(prevOut)
		log.SetFlags(prevFlags)
	})
	return logs
}

func waitForAlert(t *testing.T, logs *alertLog, text string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !logs.has(text) {
		if time.Now().After(deadline) {
			t.Fatalf("no alert with %q in %q", text, logs.messages)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// A check that failed for lack of access, in a repository then left out of
// the installation, is never re-checked: its alert has to clear anyway.
func TestNoAccessClearsWhenTheRepositoryLeavesTheInstallation(t *testing.T) {
	logs := captureAlerts(t)
	h := newHarness(t)
	ctx := context.Background()
	h.gh.Mu.Lock()
	h.gh.PRs["other#7"] = fakegh.PR{Open: true, HeadSHA: "head7", Commits: []fakegh.Commit{
		{AuthorName: "Other", AuthorID: 600, AuthorLogin: "other"},
	}}
	// GitHub refuses statuses there, but the checker has not listed the
	// installation yet, so it still tries.
	h.gh.Installed = []string{"rotki"}
	h.gh.Mu.Unlock()

	_, queue, sweeper := h.sweeper(t)
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go queue.Run(runCtx, 1)
	queue.Enqueue(check.Job{Ref: check.Ref{Repo: "other", Number: 7}})
	waitForAlert(t, logs, "The App has no access to a repository")
	if !logs.has("other#7 while setting the commit status (GitHub 403 Forbidden)") {
		t.Fatalf("alert lacks the call and status: %q", logs.messages)
	}

	sweeper.Sweep(ctx)
	waitForAlert(t, logs, "**Recovered:** The App has no access")
}

func TestPrivateRepositoriesAreSkipped(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.gh.Mu.Lock()
	h.gh.PRs["internal#3"] = fakegh.PR{Open: true, HeadSHA: "head3", Commits: []fakegh.Commit{
		{AuthorName: "Other", AuthorID: 600, AuthorLogin: "other"},
	}}
	h.gh.Private = []string{"internal"}
	h.gh.Mu.Unlock()

	// Installed on all repositories, private ones included.
	checker, queue, sweeper := h.sweeper(t)
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go queue.Run(runCtx, 1)
	sweeper.Sweep(ctx)

	if !checker.Skipped("internal") || !checker.Skipped("Internal") || checker.Skipped("rotki") {
		t.Fatal("skips the wrong repositories")
	}
	// Even asked directly, as a webhook for it would, it does nothing.
	if err := checker.CheckPR(ctx, check.Ref{Repo: "internal", Number: 3}, check.Hint{}); err != nil {
		t.Fatal(err)
	}
	h.waitFor(t, "a status on rotki#1", func() bool {
		for _, st := range h.gh.Statuses {
			if st.Repo == "rotki" {
				return true
			}
		}
		return false
	})
	h.gh.Mu.Lock()
	defer h.gh.Mu.Unlock()
	for _, st := range h.gh.Statuses {
		if st.Repo == "internal" {
			t.Fatalf("checked a private repository: %+v", st)
		}
	}
}
