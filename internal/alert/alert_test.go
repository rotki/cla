package alert

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/rotki/cla/internal/githubapp"
)

func newTestNotifier() (*Notifier, *[]string, *time.Time) {
	n := New("https://discord.invalid/webhook")
	now := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	var sent []string
	n.now = func() time.Time { return now }
	n.send = func(_ context.Context, m string) error {
		sent = append(sent, m)
		return nil
	}
	return n, &sent, &now
}

func TestReportThrottlesRepeats(t *testing.T) {
	n, sent, now := newTestNotifier()

	n.Report(StoreWrite, Detail{Status: 502})
	n.Report(StoreWrite, Detail{Status: 502})
	n.Report(StoreWrite, Detail{Status: 502})
	n.drain()
	if len(*sent) != 1 {
		t.Fatalf("want 1 message for a burst, got %d: %v", len(*sent), *sent)
	}

	*now = now.Add(30 * time.Minute)
	n.Flush()
	n.drain()
	if len(*sent) != 1 {
		t.Fatalf("summary sent before the window closed: %v", *sent)
	}

	*now = now.Add(31 * time.Minute)
	n.Flush()
	n.drain()
	if len(*sent) != 2 || !strings.Contains((*sent)[1], "2 more times") {
		t.Fatalf("want one summary of 2 repeats, got %v", *sent)
	}

	n.Flush()
	n.drain()
	if len(*sent) != 2 {
		t.Fatalf("an empty window must not send anything: %v", *sent)
	}
}

func TestResolveAnnouncesRecoveryOnce(t *testing.T) {
	n, sent, _ := newTestNotifier()

	n.Resolve(CheckFailed)
	n.drain()
	if len(*sent) != 0 {
		t.Fatalf("resolving a healthy kind sent %v", *sent)
	}

	n.Report(CheckFailed, Detail{Repo: "rotki", PR: 7})
	n.Report(CheckFailed, Detail{Repo: "rotki", PR: 8})
	n.Resolve(CheckFailed)
	n.Resolve(CheckFailed)
	n.drain()
	if len(*sent) != 2 {
		t.Fatalf("want failure and recovery, got %v", *sent)
	}
	if !strings.Contains((*sent)[1], "Recovered") || !strings.Contains((*sent)[1], "1 more failures") {
		t.Fatalf("unexpected recovery message %q", (*sent)[1])
	}
}

func TestKindsAreIndependent(t *testing.T) {
	n, sent, _ := newTestNotifier()
	n.Report(CheckFailed, Detail{})
	n.Report(StoreRead, Detail{})
	n.drain()
	if len(*sent) != 2 {
		t.Fatalf("want one message per kind, got %v", *sent)
	}
}

func TestDetailCarriesOnlyRepoPRCallAndStatus(t *testing.T) {
	cases := map[string]Detail{
		"":                                {},
		"rotki#12":                        {Repo: "rotki", PR: 12},
		"rotki":                           {Repo: "rotki"},
		"(GitHub 502 Bad Gateway)":        {Status: 502},
		"rotki#12 (GitHub 404 Not Found)": {Repo: "rotki", PR: 12, Status: 404},
		"(GitHub 599)":                    {Status: 599},
		"ui-library#644 while setting the commit status (GitHub 403 Forbidden)": {
			Repo: "ui-library", PR: 644, Call: "setting the commit status", Status: 403,
		},
	}
	for want, d := range cases {
		if got := d.String(); got != want {
			t.Errorf("Detail%+v = %q, want %q", d, got, want)
		}
	}
}

func TestReportDoesNotWaitForDiscord(t *testing.T) {
	n := New("https://discord.invalid/webhook")
	n.send = func(context.Context, string) error {
		time.Sleep(time.Hour)
		return nil
	}
	start := time.Now()
	for i := range 100 {
		n.Report(Kind(fmt.Sprintf("k%d", i)), Detail{})
	}
	if time.Since(start) > time.Second {
		t.Fatal("Report blocked on sending")
	}
}

func TestRedactDropsTheWebhookURL(t *testing.T) {
	err := &url.Error{Op: "Post", URL: "https://discord.com/api/webhooks/1/SECRET", Err: errors.New("dial tcp: timeout")}
	if got := redact(err).Error(); strings.Contains(got, "SECRET") || got != "dial tcp: timeout" {
		t.Fatalf("got %q", got)
	}
}

// drain sends whatever is queued, synchronously.
func (n *Notifier) drain() {
	for {
		select {
		case m := <-n.outbox:
			n.post1(m)
		default:
			return
		}
	}
}

func TestStoppingSendsWhatIsQueued(t *testing.T) {
	n := New("https://discord.invalid/webhook")
	var sent []string
	n.send = func(_ context.Context, m string) error {
		sent = append(sent, m)
		return nil
	}
	n.Report(CheckFailed, Detail{Repo: "rotki", PR: 1})
	n.Report(StoreRead, Detail{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	n.Run(ctx)
	if len(sent) != 2 {
		t.Fatalf("a stopping notifier sent %d of 2 queued alerts", len(sent))
	}
}

func TestForError(t *testing.T) {
	graphqlNotFound := &githubapp.GraphQLError{Count: 1, Types: []string{"NOT_FOUND"}}
	cases := []struct {
		name string
		err  error
		kind Kind
		want string
	}{
		{"status refused", &githubapp.APIError{Path: "/repos/rotki/x/statuses/abc", Status: 403}, NoAccess,
			"x#3 while setting the commit status (GitHub 403 Forbidden)"},
		{"app uninstalled", &githubapp.APIError{Path: "/app/installations/1/access_tokens", Status: 404}, NotInstalled,
			"x#3 while getting an installation token (GitHub 404 Not Found)"},
		{"graphql named by the caller", graphqlNotFound, NoAccess, "x#3 while reading the pull request"},
		{"other failure", &githubapp.APIError{Path: "/repos/rotki/x/statuses/abc", Status: 502}, CheckFailed,
			"x#3 while setting the commit status (GitHub 502 Bad Gateway)"},
	}
	for _, tc := range cases {
		kind, d := ForError(CheckFailed, tc.err, Detail{Repo: "x", PR: 3}, "reading the pull request")
		if kind != tc.kind || d.String() != tc.want {
			t.Errorf("%s: got %s %q, want %s %q", tc.name, kind, d, tc.kind, tc.want)
		}
	}
}
