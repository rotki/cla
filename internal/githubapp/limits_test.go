package githubapp

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func header(kv ...string) http.Header {
	h := http.Header{}
	for i := 0; i < len(kv); i += 2 {
		h.Set(kv[i], kv[i+1])
	}
	return h
}

func TestRateLimitedClassification(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	reset := strconv.FormatInt(now.Add(30*time.Minute).Unix(), 10)
	cases := []struct {
		name    string
		status  int
		header  http.Header
		body    string
		limited bool
		retryAt time.Time
	}{
		{"retry-after wins", 403, header("Retry-After", "90", "X-RateLimit-Remaining", "0", "X-RateLimit-Reset", reset), "", true, now.Add(90 * time.Second)},
		{"primary limit waits for the reset", 403, header("X-RateLimit-Remaining", "0", "X-RateLimit-Reset", reset), "", true, now.Add(30 * time.Minute)},
		{"secondary limit without headers", 403, header("X-RateLimit-Remaining", "4000"), `{"message":"You have exceeded a secondary rate limit"}`, true, now.Add(time.Minute)},
		{"429", 429, header(), "", true, now.Add(time.Minute)},
		{"permission error is not a limit", 403, header("X-RateLimit-Remaining", "4000"), `{"message":"Resource not accessible by integration"}`, false, time.Time{}},
		{"404 is not a limit", 404, header(), "", false, time.Time{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := &http.Response{StatusCode: tc.status, Header: tc.header}
			at, limited := rateLimited(resp, []byte(tc.body), now)
			if limited != tc.limited || !at.Equal(tc.retryAt) {
				t.Fatalf("got %v %v, want %v %v", limited, at, tc.limited, tc.retryAt)
			}
		})
	}
}

func TestRateLimitErrorKeepsTheStatus(t *testing.T) {
	err := error(&RateLimitError{APIError: APIError{Method: "POST", Path: "/x", Status: 403}, RetryAt: time.Unix(5, 0)})
	if StatusOf(err) != 403 {
		t.Fatalf("StatusOf = %d", StatusOf(err))
	}
	if at, ok := RetryAfter(err); !ok || at.Unix() != 5 {
		t.Fatalf("RetryAfter = %v %v", at, ok)
	}
	if _, ok := RetryAfter(errors.New("other")); ok {
		t.Fatal("plain error treated as a rate limit")
	}
}

func TestLimitsLow(t *testing.T) {
	l := NewLimits()
	now := time.Unix(1_800_000_000, 0)
	l.now = func() time.Time { return now }
	reset := strconv.FormatInt(now.Add(10*time.Minute).Unix(), 10)

	l.observe(header("X-RateLimit-Limit", "5000", "X-RateLimit-Remaining", "4000", "X-RateLimit-Reset", reset, "X-RateLimit-Resource", "core"))
	if low, _ := l.Low(0.1); low {
		t.Fatal("80% left reported as low")
	}

	l.observe(header("X-RateLimit-Limit", "5000", "X-RateLimit-Remaining", "300", "X-RateLimit-Reset", reset, "X-RateLimit-Resource", "graphql"))
	low, until := l.Low(0.1)
	if !low || until.Unix() != now.Add(10*time.Minute).Unix() {
		t.Fatalf("graphql at 6%% not low: %v %v", low, until)
	}

	now = now.Add(11 * time.Minute)
	if low, _ := l.Low(0.1); low {
		t.Fatal("still low after the reset")
	}
	if len(l.Snapshot()) != 2 {
		t.Fatalf("snapshot %v", l.Snapshot())
	}
}

func TestPacerSpacesWrites(t *testing.T) {
	p := NewPacer(40 * time.Millisecond)
	start := time.Now()
	for range 3 {
		if _, err := p.Wait(context.Background(), false); err != nil {
			t.Fatal(err)
		}
	}
	if elapsed := time.Since(start); elapsed < 80*time.Millisecond {
		t.Fatalf("three writes in %v, want at least two gaps", elapsed)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := p.Wait(ctx, false); err == nil {
		t.Fatal("a cancelled wait returned no error")
	}
}

func TestMutates(t *testing.T) {
	cases := map[string]bool{
		"GET /repos/x":           false,
		"POST /graphql":          false,
		"POST /markdown":         false,
		"POST /repos/x/statuses": true,
		"PATCH /repos/x/c/1":     true,
		"PUT /repos/x/contents":  true,
		"DELETE /repos/x/c":      true,
	}
	for call, want := range cases {
		method, path, _ := strings.Cut(call, " ")
		if got := mutates(method, path); got != want {
			t.Errorf("mutates(%s) = %v", call, got)
		}
	}
}

func TestPacerDoesNotHoldItsLockWhileWaiting(t *testing.T) {
	p := NewPacer(time.Hour)
	if _, err := p.Wait(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	// The next slot is an hour away; a cancelled waiter must return at once
	// and must not block a third caller from reserving its slot.
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := p.Wait(ctx, false)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("waited out an hour-long gap")
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled wait did not return")
	}
	if !p.mu.TryLock() {
		t.Fatal("the pacer lock is held by a waiter")
	}
	p.mu.Unlock()
}

func TestGraphQLRateLimitIsARateLimitError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"errors":[{"type":"RATE_LIMITED","message":"API rate limit exceeded"}]}`))
	}))
	defer srv.Close()
	c := NewPublicClient(srv.URL)
	var out struct{}
	err := c.GraphQL(context.Background(), "query{}", nil, &out)
	at, ok := RetryAfter(err)
	if !ok || at.Before(time.Now()) || strings.Contains(err.Error(), "rate limit exceeded") {
		t.Fatalf("got %v (retry %v %v)", err, at, ok)
	}
}

func TestSecondaryLimitStopsAllCalls(t *testing.T) {
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		w.Header().Set("Retry-After", "120")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"message":"You have exceeded a secondary rate limit"}`))
	}))
	defer srv.Close()

	c := NewPublicClient(srv.URL)
	c.limits = NewLimits()
	if _, err := c.Do(context.Background(), http.MethodGet, "/repos/x", nil, nil); err == nil {
		t.Fatal("no error")
	}
	for _, path := range []string{"/repos/y", "/graphql"} {
		_, err := c.Do(context.Background(), http.MethodPost, path, map[string]string{}, nil)
		if at, ok := RetryAfter(err); !ok || time.Until(at) < 100*time.Second {
			t.Fatalf("%s: %v", path, err)
		}
	}
	if hits != 1 {
		t.Fatalf("%d requests reached GitHub while limited", hits)
	}
}

func TestSpentQuotaBlocksOnlyItsResource(t *testing.T) {
	l := NewLimits()
	reset := strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10)
	l.observe(header("X-RateLimit-Limit", "5000", "X-RateLimit-Remaining", "0", "X-RateLimit-Reset", reset, "X-RateLimit-Resource", "graphql"))
	if _, blocked := l.Blocked("graphql"); !blocked {
		t.Fatal("spent graphql quota not blocking")
	}
	if _, blocked := l.Blocked("core"); blocked {
		t.Fatal("graphql quota blocked REST calls")
	}
}

func TestGraphQLLimitFromMessageOrHeaders(t *testing.T) {
	cases := map[string]struct {
		header http.Header
		body   string
	}{
		"message only":       {header(), `{"errors":[{"message":"API rate limit exceeded for installation"}]}`},
		"no quota in header": {header("X-RateLimit-Remaining", "0", "X-RateLimit-Reset", strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10)), `{"errors":[{"message":"something"}]}`},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				for k, v := range tc.header {
					w.Header()[k] = v
				}
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()
			var out struct{}
			err := NewPublicClient(srv.URL).GraphQL(context.Background(), "query{}", nil, &out)
			if _, ok := RetryAfter(err); !ok {
				t.Fatalf("not a rate limit: %v", err)
			}
		})
	}
}

func TestPacerHourlyBudget(t *testing.T) {
	p := NewPacer(0)
	p.budget, p.reserve = 3, 0
	now := time.Unix(1_800_000_000, 0)
	p.now = func() time.Time { return now }
	for range 3 {
		if _, err := p.Wait(context.Background(), false); err != nil {
			t.Fatal(err)
		}
	}
	_, err := p.Wait(context.Background(), false)
	if at, ok := RetryAfter(err); !ok || !at.Equal(now.Add(time.Hour)) {
		t.Fatalf("over budget: %v", err)
	}
	now = now.Add(time.Hour)
	if _, err := p.Wait(context.Background(), false); err != nil {
		t.Fatalf("budget not renewed: %v", err)
	}
}

func TestPacerKeepsAReserveForPeople(t *testing.T) {
	p := NewPacer(0)
	p.budget, p.reserve = 4, 2
	for range 2 {
		if _, err := p.Wait(context.Background(), false); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := p.Wait(context.Background(), false); err == nil {
		t.Fatal("background write took the reserved budget")
	}
	for range 2 {
		if _, err := p.Wait(context.Background(), true); err != nil {
			t.Fatalf("interactive write refused: %v", err)
		}
	}
	if _, err := p.Wait(context.Background(), true); err == nil {
		t.Fatal("budget exceeded")
	}

	slot := p.sent[len(p.sent)-1]
	p.Release(slot)
	if _, err := p.Wait(context.Background(), true); err != nil {
		t.Fatalf("a released slot was not reusable: %v", err)
	}
}
