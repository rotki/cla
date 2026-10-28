package check

import (
	"context"
	"errors"
	"log/slog"
	"math/rand/v2"
	"sync"
	"time"

	"github.com/rotki/cla/internal/alert"
	"github.com/rotki/cla/internal/githubapp"
)

// Job is one unit of work for the workers.
type Job struct {
	Ref Ref
	// MergeSHA is set for a merge queue commit, which needs no check.
	MergeSHA string
	// Closed drops what is remembered about a pull request that closed.
	Closed bool
	// Hint carries what the caller already knows; see Checker.CheckPR.
	Hint Hint
	// Background marks work the reconcile sweep queued. It is dropped while
	// the quota runs low; the next sweep after the reset queues it again.
	Background bool
	// Bulk marks an admin's re-check of every open pull request: it is
	// never dropped, but waits behind the work people are waiting on.
	Bulk bool
	// Signed marks the re-check after a signing or an admin's confirm or
	// reject: someone is looking at a page for its result, so its writes may
	// use the part of the budget nothing else can. Webhook jobs go first in
	// the queue too, but anyone can trigger those by pushing, so they do not
	// get the reserve.
	Signed bool
}

// jobKey names what a job works on, for retries and alerts: a pull request,
// or a merge queue commit.
type jobKey struct {
	ref Ref
	sha string
}

func (j Job) key() jobKey {
	return jobKey{j.Ref, j.MergeSHA}
}

// forPeople reports whether someone is waiting on the job: a webhook, a
// signing. Such jobs go first in the queue.
func (j Job) forPeople() bool {
	return !j.Background && !j.Bulk
}

// merge combines a job that arrived while the same pull request was being
// checked: forced if either was, for people if either was, background only
// if both were. A known status is dropped, since it described an older
// moment.
func (j Job) merge(other Job) Job {
	j.Hint.Force = j.Hint.Force || other.Hint.Force
	j.Hint.Known = nil
	people := j.forPeople() || other.forPeople()
	j.Signed = j.Signed || other.Signed
	j.Background = j.Background && other.Background
	j.Bulk = !people && !j.Background
	return j
}

// Queue runs jobs on a few workers. Jobs someone is waiting on (a webhook,
// a signing) have their own channel, which workers always empty first, so a
// signer never waits behind a sweep of every open pull request. A pull
// request already waiting is not queued twice, unless a job for people
// arrives while it waits as background work: then it is queued again with
// priority and the background copy is skipped. A pull request is checked
// by one worker at a time: events that arrive meanwhile are folded into one
// re-check by that same worker, so a burst of pushes never ties up the
// other workers.
type Queue struct {
	checker *Checker
	alerts  *alert.Notifier
	limits  *githubapp.Limits
	people  chan Job
	jobs    chan Job

	mu sync.Mutex
	// queued holds the pull requests waiting, true when the waiting job is
	// for people; superseded the background copies a job for people
	// replaced.
	queued     map[Ref]bool
	superseded map[Ref]bool
	running    map[Ref]*running
	scheduled  map[jobKey]*time.Timer
	attempts   map[jobKey]int
	// failing and limited hold what last failed or hit a limit. Each alert
	// is resolved once its set empties, not on the first job that succeeds,
	// or every success between two failures would end the alert's quiet
	// window and send another pair of messages.
	failing map[jobKey]bool
	limited map[jobKey]bool
}

// Backoff after repeated rate limits, as GitHub asks: the wait doubles from
// a minute up to an hour, and after maxAttempts the pull request is left to
// a later reconcile sweep.
const (
	backoffBase = time.Minute
	backoffMax  = time.Hour
	maxAttempts = 6
)

// running is a pull request being checked, with work that arrived meanwhile.
type running struct {
	again   bool
	pending Job
}

func NewQueue(checker *Checker, alerts *alert.Notifier, limits *githubapp.Limits, size int) *Queue {
	return &Queue{
		checker:    checker,
		alerts:     alerts,
		limits:     limits,
		people:     make(chan Job, size),
		jobs:       make(chan Job, size),
		queued:     map[Ref]bool{},
		superseded: map[Ref]bool{},
		running:    map[Ref]*running{},
		scheduled:  map[jobKey]*time.Timer{},
		attempts:   map[jobKey]int{},
		failing:    map[jobKey]bool{},
		limited:    map[jobKey]bool{},
	}
}

// Depth is the number of jobs waiting, queued or scheduled for a retry.
func (q *Queue) Depth() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.people) + len(q.jobs) + len(q.scheduled)
}

// Enqueue adds a job without blocking. It reports false when the queue is
// full; the reconcile sweep picks the pull request up later.
func (q *Queue) Enqueue(job Job) bool {
	ch := q.jobs
	if job.forPeople() {
		ch = q.people
	}
	if job.MergeSHA == "" {
		q.mu.Lock()
		forPeople, waiting := q.queued[job.Ref]
		if waiting && (forPeople || !job.forPeople()) {
			q.mu.Unlock()
			return true
		}
		if waiting {
			q.superseded[job.Ref] = true
		}
		q.queued[job.Ref] = job.forPeople()
		q.mu.Unlock()
	}
	select {
	case ch <- job:
		return true
	default:
		q.mu.Lock()
		delete(q.queued, job.Ref)
		delete(q.superseded, job.Ref)
		q.mu.Unlock()
		slog.Warn("job queue full, leaving the pull request to the reconcile sweep", "pr", job.Ref.String())
		return false
	}
}

// drainTime is how long checks in progress may run on after a shutdown
// begins.
const drainTime = 10 * time.Second

// Run starts n workers and returns when ctx is done and they have stopped.
// Once ctx is done, workers take no new jobs, but a check in progress keeps
// going for up to drainTime rather than being cut off halfway through its
// writes. Jobs still waiting are dropped: the queue holds only what to
// re-check, and the sweep after the next start finds those again.
func (q *Queue) Run(ctx context.Context, n int) {
	work, cancel := context.WithCancel(context.WithoutCancel(ctx))
	defer cancel()
	stopped := context.AfterFunc(ctx, func() { time.AfterFunc(drainTime, cancel) })
	defer stopped()

	var wg sync.WaitGroup
	for range n {
		wg.Go(func() {
			for {
				if ctx.Err() != nil {
					return
				}
				select {
				case job := <-q.people:
					q.handle(work, job)
					continue
				default:
				}
				select {
				case <-ctx.Done():
					return
				case job := <-q.people:
					q.handle(work, job)
				case job := <-q.jobs:
					q.handle(work, job)
				}
			}
		})
	}
	wg.Wait()
}

func (q *Queue) handle(ctx context.Context, job Job) {
	if job.MergeSHA != "" {
		// Only people with write access can queue a merge, and the queue
		// waits on this status, so it may use the reserve.
		err := q.checker.PassMergeGroup(githubapp.WithInteractive(ctx), job.Ref.Repo, job.MergeSHA)
		q.report(err, job)
		return
	}
	if !job.forPeople() {
		q.mu.Lock()
		if q.superseded[job.Ref] {
			delete(q.superseded, job.Ref)
			q.mu.Unlock()
			return
		}
		// In the same step this job stops counting as the one waiting, so a
		// job for people arriving from now on is queued as usual instead of
		// marking this one superseded after it already started.
		if forPeople, waiting := q.queued[job.Ref]; waiting && !forPeople {
			delete(q.queued, job.Ref)
		}
		q.mu.Unlock()
	}
	if job.Closed {
		q.mu.Lock()
		delete(q.queued, job.Ref)
		key := job.key()
		if t, ok := q.scheduled[key]; ok {
			t.Stop()
			delete(q.scheduled, key)
		}
		delete(q.attempts, key)
		delete(q.failing, key)
		delete(q.limited, key)
		q.mu.Unlock()
		q.checker.Forget(job.Ref)
		return
	}
	if job.Background && q.limits != nil {
		if low, _ := q.limits.Low(githubapp.LowQuota); low {
			return
		}
	}

	q.mu.Lock()
	// A background job already gave up its place above; deleting here could
	// drop the place of a job for people queued since.
	if forPeople, waiting := q.queued[job.Ref]; waiting && forPeople == job.forPeople() {
		delete(q.queued, job.Ref)
	}
	if r, busy := q.running[job.Ref]; busy {
		// Another worker is on it: leave a note and move on.
		if r.again {
			r.pending = r.pending.merge(job)
		} else {
			r.again, r.pending = true, job
		}
		q.mu.Unlock()
		return
	}
	r := &running{}
	q.running[job.Ref] = r
	q.mu.Unlock()

	for {
		// A re-check someone is waiting on after signing may use the writes
		// kept back for people; see Job.Signed.
		jobCtx := ctx
		if job.Signed {
			jobCtx = githubapp.WithInteractive(ctx)
		}
		err := q.checker.CheckPR(jobCtx, job.Ref, job.Hint)
		q.report(err, job)

		q.mu.Lock()
		if !r.again || ctx.Err() != nil {
			delete(q.running, job.Ref)
			q.mu.Unlock()
			return
		}
		job, r.again = r.pending, false
		q.mu.Unlock()
	}
}

func (q *Queue) report(err error, job Job) {
	ref, key := job.Ref, job.key()
	if err == nil {
		q.mu.Lock()
		delete(q.attempts, key)
		delete(q.failing, key)
		delete(q.limited, key)
		failing, limited := len(q.failing), len(q.limited)
		q.mu.Unlock()
		if failing == 0 {
			q.resolveChecks()
		}
		if limited == 0 {
			q.alerts.Resolve(alert.RateLimited)
		}
		return
	}
	if errors.Is(err, context.Canceled) {
		return
	}
	if errors.Is(err, ErrNotReady) {
		q.retryAt(job, time.Now().Add(30*time.Second))
		return
	}
	if retryAt, limited := githubapp.RetryAfter(err); limited {
		// Never wait out a limit on a worker: reschedule and move on.
		slog.Warn("rate limited, rescheduling", "pr", ref.String(), "retry_at", retryAt)
		q.mu.Lock()
		q.limited[key] = true
		q.mu.Unlock()
		q.alerts.Report(alert.RateLimited, alert.Detail{Status: githubapp.StatusOf(err)})
		q.retryAt(job, retryAt)
		return
	}
	slog.Error("check failed", "pr", ref.String(), "call", githubapp.Call(err), "error", err)
	q.mu.Lock()
	q.failing[key] = true
	q.mu.Unlock()
	// A check's only GraphQL request reads the pull request and its commits.
	q.alerts.ReportError(alert.CheckFailed, err, alert.Detail{Repo: ref.Repo, PR: ref.Number}, "reading the pull request")
}

// resolveChecks announces recovery for every alert a failing check can
// raise, once none is failing any more.
func (q *Queue) resolveChecks() {
	q.alerts.Resolve(alert.CheckFailed)
	q.alerts.Resolve(alert.NoAccess)
	q.alerts.Resolve(alert.NotInstalled)
}

// ForgetSkipped drops what the queue holds for repositories that are now
// skipped, such as one removed from the installation. Nothing re-checks
// them, so a failure recorded there would otherwise keep its alert open for
// good. Called after each listing of the installation's repositories.
func (q *Queue) ForgetSkipped() {
	q.mu.Lock()
	repos := map[string]bool{}
	for _, keys := range []map[jobKey]bool{q.failing, q.limited} {
		for key := range keys {
			repos[key.ref.Repo] = true
		}
	}
	for key := range q.attempts {
		repos[key.ref.Repo] = true
	}
	q.mu.Unlock()

	// Asked without holding q.mu: Skipped takes the checker's lock.
	skipped := map[string]bool{}
	for repo := range repos {
		if q.checker.Skipped(repo) {
			skipped[repo] = true
		}
	}
	if len(skipped) == 0 {
		return
	}

	q.mu.Lock()
	for key, t := range q.scheduled {
		if skipped[key.ref.Repo] {
			t.Stop()
			delete(q.scheduled, key)
		}
	}
	for _, keys := range []map[jobKey]bool{q.failing, q.limited} {
		for key := range keys {
			if skipped[key.ref.Repo] {
				delete(keys, key)
			}
		}
	}
	for key := range q.attempts {
		if skipped[key.ref.Repo] {
			delete(q.attempts, key)
		}
	}
	failing, limited := len(q.failing), len(q.limited)
	q.mu.Unlock()
	if failing == 0 {
		q.resolveChecks()
	}
	if limited == 0 {
		q.alerts.Resolve(alert.RateLimited)
	}
}

func backoff(attempt int) time.Duration {
	d := backoffBase << (attempt - 1)
	if d <= 0 || d > backoffMax {
		return backoffMax
	}
	return d
}

// retryAt queues job again once the limit has reset. One timer per pull
// request or merge queue commit: GitHub does not deliver a webhook twice,
// and the sweep finds only pull requests, so a merge queue commit gets its
// status from these retries or not at all.
func (q *Queue) retryAt(job Job, at time.Time) {
	key := job.key()
	q.mu.Lock()
	defer q.mu.Unlock()
	if _, ok := q.scheduled[key]; ok {
		return
	}
	q.attempts[key]++
	n := q.attempts[key]
	if n > maxAttempts {
		delete(q.attempts, key)
		delete(q.limited, key)
		slog.Warn("giving up until the next sweep", "pr", job.Ref.String(), "merge_sha", job.MergeSHA)
		return
	}
	delay := max(time.Until(at), backoff(n))
	// Up to 20% jitter, so retries scheduled for the same reset do not all
	// fire in the same second, the burst GitHub's secondary limits punish.
	delay += time.Second + time.Duration(rand.Int64N(int64(delay)/5+1))
	retry := job
	retry.Hint.Known = nil
	q.scheduled[key] = time.AfterFunc(delay, func() {
		q.mu.Lock()
		delete(q.scheduled, key)
		q.mu.Unlock()
		q.Enqueue(retry)
	})
}
