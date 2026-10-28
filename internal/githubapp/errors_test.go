package githubapp

import (
	"fmt"
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
