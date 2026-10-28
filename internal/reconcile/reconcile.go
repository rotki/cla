// Package reconcile sweeps open pull requests on a timer.
//
// Webhooks get lost: a restart drops the in-memory queue, a deploy misses a
// delivery, GitHub has an incident. cla-assistant failed silently in exactly
// that way. The sweep re-queues every open pull request whose head does not
// carry a successful status from us, so a lost event costs minutes, not a
// stuck pull request. It also refreshes the store, which picks up changes
// cla-tool made to the data directory and hand edits to its settings, and
// warms the CLA text so public pages never call GitHub.
//
// The sweep is background work: it stops while the quota runs low, finds the
// open pull requests with one org-wide search, and skips pull requests
// already checked at their current head with the current inputs.
package reconcile

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/rotki/cla/internal/alert"
	"github.com/rotki/cla/internal/check"
	"github.com/rotki/cla/internal/githubapp"
	"github.com/rotki/cla/internal/store"
)

// openPRsQuery finds open pull requests with one search across the org, so
// a sweep costs a couple of points whatever the number of repos. Search sees
// only repos the installation can access. Its 1,000 result cap is far above
// rotki's open pull requests; past it pruning is skipped.
const openPRsQuery = `query($query: String!, $cursor: String, $context: String!) {
  search(type: ISSUE, query: $query, first: 100, after: $cursor) {
    issueCount
    pageInfo { hasNextPage endCursor }
    nodes {
      ... on PullRequest {
        number
        headRefOid
        repository { name }
        commits(last: 1) { nodes { commit { status { context(name: $context) { state description } } } } }
      }
    }
  }
}`

// searchLimit is GitHub's cap on search results.
const searchLimit = 1000

type Sweeper struct {
	gh        *githubapp.Client
	store     *store.Store
	agreement *store.Agreement
	checker   *check.Checker
	queue     *check.Queue
	alerts    *alert.Notifier
	limits    *githubapp.Limits
	owner     string

	// reposMu serialises ReposChanged: each webhook delivery about the
	// installation's repositories calls it from its own goroutine.
	reposMu sync.Mutex
}

func New(gh *githubapp.Client, st *store.Store, agreement *store.Agreement, checker *check.Checker, queue *check.Queue, alerts *alert.Notifier, limits *githubapp.Limits, owner string) *Sweeper {
	return &Sweeper{
		gh: gh, store: st, agreement: agreement, checker: checker, queue: queue,
		alerts: alerts, limits: limits, owner: owner,
	}
}

// Run sweeps once at start and then every interval until ctx is done.
func (s *Sweeper) Run(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		s.Sweep(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// Sweep refreshes the store and the CLA text, then queues every open pull
// request that needs a check and forgets the ones that closed. While the
// quota runs low only the refresh runs: it reads the data directory, and
// the CLA text comes from the gist, outside the App's quota.
func (s *Sweeper) Sweep(ctx context.Context) {
	start := time.Now()
	if err := s.store.Refresh(ctx); err != nil {
		if s.limited(err) {
			return
		}
		slog.Error("refreshing the signatures store failed", "error", err)
		s.alerts.Report(alert.StoreRead, alert.Detail{Status: githubapp.StatusOf(err)})
		if !s.store.Ready() {
			return
		}
	} else {
		s.alerts.Resolve(alert.StoreRead)
	}
	if err := s.agreement.Warm(ctx, s.store.Config()); err != nil {
		slog.Error("loading the CLA text failed", "error", err)
	}
	if low, until := s.limits.Low(githubapp.LowQuota); low {
		slog.Warn("quota low, skipping the reconcile sweep", "until", until)
		return
	}
	if err := s.checker.RefreshTeam(ctx); err != nil {
		if s.limited(err) {
			return
		}
		// The sweep goes on with the team as last fetched.
		slog.Warn("refreshing the exempt team failed", "error", err)
	}
	if err := s.checker.RefreshRepos(ctx); err != nil {
		if s.limited(err) {
			return
		}
		// The sweep goes on with the repositories as last listed.
		slog.Warn("listing the installation's repositories failed", "error", err)
	} else {
		s.queue.ForgetSkipped()
	}

	open, complete, err := s.sweep(ctx, s.orgQuery(), false)
	if err != nil {
		s.fail(ctx, err, "")
		return
	}
	if complete {
		s.checker.Prune(open, start.Add(-searchLag))
	}
	s.alerts.Resolve(alert.ReconcileError)
	// The search needed an installation token, so the App is installed.
	s.alerts.Resolve(alert.NotInstalled)
}

// SweepRepo queues the open pull requests of one repository, for one newly
// added to the installation.
func (s *Sweeper) SweepRepo(ctx context.Context, repo string) error {
	_, _, err := s.sweep(ctx, fmt.Sprintf("repo:%s/%s is:pr is:open is:public", s.owner, repo), false)
	return err
}

// ReposChanged follows repositories added to or removed from the
// installation: it lists them again, so removed ones are skipped from now on,
// then queues the open pull requests of each added one.
func (s *Sweeper) ReposChanged(ctx context.Context, added []string) {
	s.reposMu.Lock()
	defer s.reposMu.Unlock()
	if err := s.checker.RefreshRepos(ctx); err != nil {
		slog.Warn("listing the installation's repositories failed", "error", err)
	} else {
		s.queue.ForgetSkipped()
	}
	for _, repo := range added {
		if err := s.SweepRepo(ctx, repo); err != nil {
			slog.Error("sweeping a newly added repository failed", "repo", repo, "error", err)
		}
	}
}

// searchLag is how far GitHub's search index may trail the events: a pull
// request checked this long before a sweep may still be missing from it.
const searchLag = 5 * time.Minute

// orgQuery finds the open pull requests of the org's public repositories:
// private ones are never checked (see check.Checker.Skipped).
func (s *Sweeper) orgQuery() string {
	return fmt.Sprintf("org:%s is:pr is:open is:public archived:false", s.owner)
}

// RecheckAll is the manual re-check: it forgets what was checked before and
// queues every open pull request, green ones included, as bulk work: never
// dropped for a low quota, but behind anything a signer is waiting on.
// The status GitHub shows is passed along, so a pull request whose result is
// unchanged still costs no write. It returns how many were queued.
func (s *Sweeper) RecheckAll(ctx context.Context) (int, error) {
	if err := s.store.Refresh(ctx); err != nil {
		return 0, err
	}
	start := time.Now()
	s.checker.ForgetResults()
	open, complete, err := s.sweep(ctx, s.orgQuery(), true)
	if err != nil {
		return 0, err
	}
	if complete {
		s.checker.Prune(open, start.Add(-searchLag))
	}
	return len(open), nil
}

// sweep queues the pull requests a search finds that have no successful
// status from us and were not already checked at their head, or with all
// set, every one of them. It returns the open pull requests seen, and
// whether that list is complete.
func (s *Sweeper) sweep(ctx context.Context, query string, all bool) (open map[check.Ref]bool, complete bool, err error) {
	open = map[check.Ref]bool{}
	var cursor *string
	for {
		var data struct {
			Search struct {
				IssueCount int `json:"issueCount"`
				PageInfo   struct {
					HasNextPage bool   `json:"hasNextPage"`
					EndCursor   string `json:"endCursor"`
				} `json:"pageInfo"`
				Nodes []struct {
					Number     int    `json:"number"`
					HeadRefOid string `json:"headRefOid"`
					Repository struct {
						Name string `json:"name"`
					} `json:"repository"`
					Commits struct {
						Nodes []headCommit `json:"nodes"`
					} `json:"commits"`
				} `json:"nodes"`
			} `json:"search"`
		}
		vars := map[string]any{"query": query, "cursor": cursor, "context": s.checker.Context()}
		if err := s.gh.GraphQL(ctx, openPRsQuery, vars, &data); err != nil {
			return open, false, err
		}
		for _, pr := range data.Search.Nodes {
			if pr.Number == 0 || s.checker.Skipped(pr.Repository.Name) {
				continue
			}
			ref := check.Ref{Repo: pr.Repository.Name, Number: pr.Number}
			open[ref] = true
			known := knownStatus(pr.Commits.Nodes)
			switch {
			case all:
				s.queue.Enqueue(check.Job{Ref: ref, Bulk: true, Hint: check.Hint{Known: known.On(pr.HeadRefOid), Force: known == nil}})
			case known == nil:
				// No status from us at all, whatever we remember: report again.
				s.queue.Enqueue(check.Job{Ref: ref, Background: true, Hint: check.Hint{Force: true}})
			case known.State == "success":
			case !s.checker.UpToDate(ref, pr.HeadRefOid):
				s.queue.Enqueue(check.Job{Ref: ref, Background: true, Hint: check.Hint{Known: known.On(pr.HeadRefOid)}})
			}
		}
		if !data.Search.PageInfo.HasNextPage {
			return open, data.Search.IssueCount <= searchLimit, nil
		}
		end := data.Search.PageInfo.EndCursor
		cursor = &end
	}
}

// headCommit is the last commit of a pull request with our status on it.
type headCommit struct {
	Commit struct {
		Status *struct {
			Context *struct {
				State       string `json:"state"`
				Description string `json:"description"`
			} `json:"context"`
		} `json:"status"`
	} `json:"commit"`
}

// knownStatus is our status on the head commit, or nil when there is none.
func knownStatus(nodes []headCommit) *check.Status {
	if len(nodes) == 0 {
		return nil
	}
	st := nodes[0].Commit.Status
	if st == nil || st.Context == nil {
		return nil
	}
	return &check.Status{State: strings.ToLower(st.Context.State), Description: st.Context.Description}
}

// limited reports and swallows a rate limit; the next sweep after the reset
// carries on.
func (s *Sweeper) limited(err error) bool {
	if _, ok := githubapp.RetryAfter(err); !ok {
		return false
	}
	slog.Warn("rate limited during the reconcile sweep", "error", err)
	s.alerts.Report(alert.RateLimited, alert.Detail{Status: githubapp.StatusOf(err)})
	return true
}

func (s *Sweeper) fail(ctx context.Context, err error, repo string) {
	if ctx.Err() != nil || errors.Is(err, context.Canceled) || s.limited(err) {
		return
	}
	slog.Error("reconcile sweep failed", "repo", repo, "call", githubapp.Call(err), "error", err)
	// The sweep's GraphQL request is the search for open pull requests.
	s.alerts.ReportError(alert.ReconcileError, err, alert.Detail{Repo: repo}, "searching for open pull requests")
}
