package githubapp

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNoAccess(t *testing.T) {
	cases := []struct {
		err  error
		want bool
	}{
		{&APIError{Method: "POST", Path: "/repos/rotki/x/statuses/abc", Status: 403}, true},
		{fmt.Errorf("checking: %w", &APIError{Status: 404}), true},
		{&APIError{Status: 500}, false},
		{&APIError{Status: 422}, false},
		// A 403 that is a rate limit is not a missing installation.
		{&RateLimitError{APIError: APIError{Status: 403}, RetryAt: time.Now()}, false},
		{&GraphQLError{Count: 1, Types: []string{"NOT_FOUND"}}, true},
		{&GraphQLError{Count: 1, Types: []string{"FORBIDDEN"}}, true},
		{&GraphQLError{Count: 1, Types: []string{"INTERNAL"}}, false},
		{fmt.Errorf("plain"), false},
	}
	for _, tc := range cases {
		if got := NoAccess(tc.err); got != tc.want {
			t.Errorf("NoAccess(%v) = %v, want %v", tc.err, got, tc.want)
		}
	}
}

func TestNotInstalled(t *testing.T) {
	token := "/app/installations/1/access_tokens"
	if !NotInstalled(&APIError{Path: token, Status: 404}) || !NotInstalled(&APIError{Path: token, Status: 403}) {
		t.Fatal("a refused installation token is not a missing installation")
	}
	if NotInstalled(&APIError{Path: token, Status: 500}) || NotInstalled(&APIError{Path: "/repos/rotki/x/statuses/abc", Status: 404}) {
		t.Fatal("other failures read as a missing installation")
	}
	// The whole installation missing is not one repository's access.
	if NoAccess(&APIError{Path: token, Status: 404}) {
		t.Fatal("a missing installation reads as no access to a repository")
	}
}

func TestCall(t *testing.T) {
	cases := map[string]error{
		"setting the commit status":               &APIError{Path: "/repos/rotki/x/statuses/abc"},
		"reading or writing the bot comment":      &APIError{Path: "/repos/rotki/x/issues/1/comments"},
		"reading the exempt team":                 &APIError{Path: "/orgs/rotki/teams/core/members"},
		"getting an installation token":           &APIError{Path: "/app/installations/1/access_tokens"},
		"listing the installation's repositories": &APIError{Path: "/installation/repositories?per_page=100&page=1"},
		"reading from GitHub's GraphQL API":       &GraphQLError{Count: 1},
		"":                                        fmt.Errorf("plain"),
	}
	for want, err := range cases {
		if got := Call(err); got != want {
			t.Errorf("Call(%v) = %q, want %q", err, got, want)
		}
	}
}

func TestTransient(t *testing.T) {
	cases := []struct {
		err  error
		want bool
	}{
		{fmt.Errorf("github GET /x: %w", &transportError{fmt.Errorf("connection reset")}), true},
		{&APIError{Status: 502}, true},
		{&RateLimitError{APIError: APIError{Status: 403}, RetryAt: time.Now()}, true},
		{&APIError{Status: 401}, false},
		{&APIError{Status: 422}, false},
		// No status, but no blip either: access is missing, or the error
		// never came from a call to GitHub.
		{&GraphQLError{Count: 1, Types: []string{"NOT_FOUND"}}, false},
		{&GraphQLError{Count: 1, Types: []string{"FORBIDDEN"}}, false},
		{&GraphQLError{Count: 2, Types: []string{"", "NOT_FOUND"}}, false},
		{fmt.Errorf("writing the journal: disk full"), false},
		// An untyped GraphQL error is GitHub failing on its side.
		{&GraphQLError{Count: 1, Types: []string{""}}, true},
	}
	for _, tc := range cases {
		if got := Transient(tc.err); got != tc.want {
			t.Errorf("Transient(%v) = %v, want %v", tc.err, got, tc.want)
		}
	}

	// A call that reaches nobody is transient.
	srv := httptest.NewServer(http.NotFoundHandler())
	srv.Close()
	_, err := NewPublicClient(srv.URL).Do(context.Background(), http.MethodGet, "/meta", nil, nil)
	if err == nil || !Transient(err) {
		t.Fatalf("a refused connection: Transient(%v) = false", err)
	}

	// So is an answer cut off partway, but not one that is whole and wrong.
	for body, cut := range map[string]bool{`{"hooks":`: true, `not json`: false} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			if cut {
				// Promise more than is sent, so the connection ends early.
				w.Header().Set("Content-Length", "100")
			}
			_, _ = w.Write([]byte(body))
		}))
		var out map[string]any
		_, err := NewPublicClient(srv.URL).Do(context.Background(), http.MethodGet, "/meta", nil, &out)
		srv.Close()
		if err == nil || Transient(err) != cut {
			t.Errorf("body %q: Transient(%v) = %v, want %v", body, err, !cut, cut)
		}
	}

	// Any read failure that is not a whole, undecodable body counts, an
	// HTTP/2 stream reset included.
	if !Transient(readFailed(errors.New("stream error: stream ID 3; INTERNAL_ERROR"))) {
		t.Error("a reset stream is not transient")
	}

	// A certificate that fails verification is not a blip.
	tlsSrv := httptest.NewTLSServer(http.NotFoundHandler())
	_, err = NewPublicClient(tlsSrv.URL).Do(context.Background(), http.MethodGet, "/meta", nil, nil)
	tlsSrv.Close()
	if err == nil || Transient(err) {
		t.Errorf("an untrusted certificate: Transient(%v) = true", err)
	}
}

func TestGraphQLErrorsTellRejectedQueriesFromBlips(t *testing.T) {
	for body, want := range map[string]bool{
		`{"errors":[{"message":"Something went wrong while executing your query."}]}`:               true,
		`{"errors":[{"message":"Field 'x' doesn't exist","extensions":{"code":"undefinedField"}}]}`: false,
		`{"errors":[{"type":"NOT_FOUND","message":"Could not resolve to a Repository"}]}`:           false,
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(body))
		}))
		var out map[string]any
		err := NewPublicClient(srv.URL).GraphQL(context.Background(), "query{x}", nil, &out)
		srv.Close()
		if err == nil || Transient(err) != want {
			t.Errorf("%s: Transient(%v) = %v, want %v", body, err, !want, want)
		}
	}
}

func TestRevokeRetriesADroppedConnection(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		if calls < 3 {
			conn, _, _ := w.(http.Hijacker).Hijack()
			_ = conn.Close()
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	o := &OAuth{ClientID: "id", ClientSecret: "s", APIURL: srv.URL, RevokeDelays: []time.Duration{time.Millisecond, time.Millisecond}}
	if err := o.Revoke(context.Background(), "token"); err != nil || calls != 3 {
		t.Fatalf("Revoke = %v after %d calls, want success on the third", err, calls)
	}
}
