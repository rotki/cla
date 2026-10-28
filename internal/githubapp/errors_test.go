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
