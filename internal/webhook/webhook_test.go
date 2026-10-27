package webhook

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rotki/cla/internal/alert"
	"github.com/rotki/cla/internal/check"
)

type fakeQueue struct{ jobs []check.Job }

func (q *fakeQueue) Enqueue(job check.Job) bool {
	q.jobs = append(q.jobs, job)
	return true
}

var secret = []byte("s3cret")

func sign(body string) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(body))
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func deliver(h http.Handler, event, delivery, body, signature string) int {
	req := httptest.NewRequest(http.MethodPost, "/webhook", strings.NewReader(body))
	req.Header.Set("X-GitHub-Event", event)
	req.Header.Set("X-GitHub-Delivery", delivery)
	req.Header.Set("X-Hub-Signature-256", signature)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code
}

func newHandler() (*Handler, *fakeQueue) {
	q := &fakeQueue{}
	return New(secret, func() int64 { return 42 }, q, alert.New(""), nil), q
}

func TestValid(t *testing.T) {
	body := []byte(`{"a":1}`)
	if !Valid(secret, body, sign(string(body))) {
		t.Fatal("valid signature rejected")
	}
	for _, bad := range []string{"", "sha1=abc", "sha256=zz", sign(`{"a":2}`)} {
		if Valid(secret, body, bad) {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestPullRequestEventsQueueChecks(t *testing.T) {
	h, q := newHandler()
	body := `{"action":"synchronize","installation":{"id":42},"repository":{"name":"rotki"},"pull_request":{"number":13464}}`
	if code := deliver(h, "pull_request", "d1", body, sign(body)); code != http.StatusAccepted {
		t.Fatalf("status %d", code)
	}
	if len(q.jobs) != 1 || q.jobs[0].Ref != (check.Ref{Repo: "rotki", Number: 13464}) {
		t.Fatalf("jobs %+v", q.jobs)
	}

	// A redelivery of the same event is ignored.
	deliver(h, "pull_request", "d1", body, sign(body))
	if len(q.jobs) != 1 {
		t.Fatalf("redelivery queued again: %+v", q.jobs)
	}

	closed := `{"action":"closed","installation":{"id":42},"repository":{"name":"rotki"},"pull_request":{"number":1}}`
	deliver(h, "pull_request", "d2", closed, sign(closed))
	if len(q.jobs) != 2 || !q.jobs[1].Closed {
		t.Fatalf("a closed PR should queue a cleanup job: %+v", q.jobs)
	}

	labeled := `{"action":"labeled","installation":{"id":42},"repository":{"name":"rotki"},"pull_request":{"number":1}}`
	deliver(h, "pull_request", "d3", labeled, sign(labeled))
	if len(q.jobs) != 2 {
		t.Fatalf("an unrelated action queued work: %+v", q.jobs)
	}

	// A title edit changes no commits; a new base does.
	title := `{"action":"edited","installation":{"id":42},"repository":{"name":"rotki"},"pull_request":{"number":1},"changes":{"title":{"from":"old"}}}`
	deliver(h, "pull_request", "d4", title, sign(title))
	if len(q.jobs) != 2 {
		t.Fatalf("a title edit queued work: %+v", q.jobs)
	}
	null := `{"action":"edited","installation":{"id":42},"repository":{"name":"rotki"},"pull_request":{"number":1},"changes":{"base":null}}`
	deliver(h, "pull_request", "d6", null, sign(null))
	if len(q.jobs) != 2 {
		t.Fatalf("a null base queued work: %+v", q.jobs)
	}
	base := `{"action":"edited","installation":{"id":42},"repository":{"name":"rotki"},"pull_request":{"number":1},"changes":{"base":{"ref":{"from":"develop"},"sha":{"from":"abc"}}}}`
	deliver(h, "pull_request", "d5", base, sign(base))
	if len(q.jobs) != 3 || q.jobs[2].Ref != (check.Ref{Repo: "rotki", Number: 1}) {
		t.Fatalf("a base change queued no check: %+v", q.jobs)
	}
}

func TestMergeGroupPassesThrough(t *testing.T) {
	h, q := newHandler()
	body := `{"action":"checks_requested","installation":{"id":42},"repository":{"name":"rotki"},"merge_group":{"head_sha":"abc"}}`
	deliver(h, "merge_group", "m1", body, sign(body))
	if len(q.jobs) != 1 || q.jobs[0].MergeSHA != "abc" {
		t.Fatalf("jobs %+v", q.jobs)
	}
}

func TestRejectsBadSignatureAndOtherInstallations(t *testing.T) {
	h, q := newHandler()
	body := `{"action":"opened","installation":{"id":42},"repository":{"name":"rotki"},"pull_request":{"number":1}}`
	if code := deliver(h, "pull_request", "x1", body, sign(body+" ")); code != http.StatusUnauthorized {
		t.Fatalf("bad signature got %d", code)
	}

	other := `{"action":"opened","installation":{"id":7},"repository":{"name":"rotki"},"pull_request":{"number":1}}`
	deliver(h, "pull_request", "x2", other, sign(other))
	if len(q.jobs) != 0 {
		t.Fatalf("queued %+v", q.jobs)
	}
}

func TestOversizedBodyIsRefusedBeforeVerification(t *testing.T) {
	h, q := newHandler()
	body := strings.Repeat("x", maxPayload+1)
	if code := deliver(h, "pull_request", "big", body, sign(body)); code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status %d", code)
	}
	if len(q.jobs) != 0 {
		t.Fatal("queued work from an oversized body")
	}
}
