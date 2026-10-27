package githubapp

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// RateLimitError is a call refused because a primary or secondary rate limit
// was hit. Callers never wait it out inside a request: they fail fast and
// leave the work for later, after RetryAt.
type RateLimitError struct {
	APIError
	RetryAt time.Time
}

func (e *RateLimitError) Error() string {
	return e.APIError.Error() + " (rate limited)"
}

func (e *RateLimitError) Unwrap() error {
	return &e.APIError
}

// RetryAfter returns when a rate-limited call may be retried.
func RetryAfter(err error) (time.Time, bool) {
	var rl *RateLimitError
	if errors.As(err, &rl) {
		return rl.RetryAt, true
	}
	return time.Time{}, false
}

// rateLimited classifies a refused response, following GitHub's guidance: a
// Retry-After header wins; with no quota left, wait for X-RateLimit-Reset; a
// secondary limit without either means waiting at least a minute.
func rateLimited(resp *http.Response, body []byte, now time.Time) (time.Time, bool) {
	if resp.StatusCode != http.StatusForbidden && resp.StatusCode != http.StatusTooManyRequests {
		return time.Time{}, false
	}
	if at, ok := retryTime(resp.Header, now); ok {
		return at, true
	}
	if resp.StatusCode == http.StatusTooManyRequests || bytes.Contains(bytes.ToLower(body), []byte("rate limit")) {
		return now.Add(time.Minute), true
	}
	return time.Time{}, false
}

// retryTime reads when to retry from the headers of a limited response.
func retryTime(h http.Header, now time.Time) (time.Time, bool) {
	if secs, err := strconv.Atoi(h.Get("Retry-After")); err == nil {
		return now.Add(time.Duration(secs) * time.Second), true
	}
	if h.Get("X-RateLimit-Remaining") == "0" {
		if reset, err := strconv.ParseInt(h.Get("X-RateLimit-Reset"), 10, 64); err == nil {
			return time.Unix(reset, 0), true
		}
	}
	return time.Time{}, false
}

// secondary reports whether a limited response was a secondary limit, which
// GitHub applies to the integration as a whole rather than to one resource.
func secondary(h http.Header) bool {
	return h.Get("X-RateLimit-Remaining") != "0"
}

// Quota is the last seen rate limit state of one resource (core, graphql).
type Quota struct {
	Limit     int       `json:"limit"`
	Remaining int       `json:"remaining"`
	Reset     time.Time `json:"reset"`
}

// Limits remembers the quota GitHub reports on every response, so background
// work can stop before the quota runs out instead of after.
type Limits struct {
	mu        sync.Mutex
	resources map[string]Quota
	// blockedUntil holds every call back after a secondary limit. GitHub
	// warns that requests sent while limited can get an integration banned.
	blockedUntil time.Time
	now          func() time.Time
}

func NewLimits() *Limits {
	return &Limits{resources: map[string]Quota{}, now: time.Now}
}

func (l *Limits) observe(h http.Header) {
	limit, err1 := strconv.Atoi(h.Get("X-RateLimit-Limit"))
	remaining, err2 := strconv.Atoi(h.Get("X-RateLimit-Remaining"))
	reset, err3 := strconv.ParseInt(h.Get("X-RateLimit-Reset"), 10, 64)
	if err1 != nil || err2 != nil || err3 != nil || limit <= 0 {
		return
	}
	resource := h.Get("X-RateLimit-Resource")
	if resource == "" {
		resource = "core"
	}
	l.mu.Lock()
	l.resources[resource] = Quota{Limit: limit, Remaining: remaining, Reset: time.Unix(reset, 0)}
	l.mu.Unlock()
}

// Low reports whether any resource has less than fraction of its quota left,
// and until when to hold off.
func (l *Limits) Low(fraction float64) (bool, time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	var until time.Time
	for _, q := range l.resources {
		if q.Reset.Before(now) {
			continue
		}
		if float64(q.Remaining) < fraction*float64(q.Limit) && q.Reset.After(until) {
			until = q.Reset
		}
	}
	return !until.IsZero(), until
}

// Block stops all calls until the given time.
func (l *Limits) Block(until time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if until.After(l.blockedUntil) {
		l.blockedUntil = until
	}
}

// Blocked reports whether a call against resource must not go out yet: a
// secondary limit is in force, or the resource's quota is spent.
func (l *Limits) Blocked(resource string) (time.Time, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	until := time.Time{}
	if l.blockedUntil.After(now) {
		until = l.blockedUntil
	}
	if q, ok := l.resources[resource]; ok && q.Remaining <= 0 && q.Reset.After(now) && q.Reset.After(until) {
		until = q.Reset
	}
	return until, !until.IsZero()
}

// Snapshot copies the current state, for /ready.
func (l *Limits) Snapshot() map[string]Quota {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make(map[string]Quota, len(l.resources))
	for k, v := range l.resources {
		out[k] = v
	}
	return out
}

// Pacer spaces out writes. GitHub asks integrations to make mutating calls
// one at a time and about a second apart, to stay clear of secondary limits.
//
// It also keeps writes under GitHub's content-creation limit (about 80 a
// minute and 500 an hour, web UI actions included) with an hourly budget
// that leaves headroom for people working in the same org.
type Pacer struct {
	mu      sync.Mutex
	gap     time.Duration
	next    time.Time
	budget  int
	reserve int
	sent    []time.Time
	now     func() time.Time
}

// WriteBudget is the most writes the service makes in any hour, and
// InteractiveReserve the part of it only interactive writes (signing, admin
// actions) may use, so a burst of checks cannot lock contributors out.
const (
	WriteBudget        = 400
	InteractiveReserve = 50
)

func NewPacer(gap time.Duration) *Pacer {
	return &Pacer{gap: gap, budget: WriteBudget, reserve: InteractiveReserve, now: time.Now}
}

// Wait blocks until this caller's write slot comes up, or ctx ends, and
// returns the slot. Slots are handed out in arrival order and the lock is not
// held while sleeping, so one slow caller never holds up the others.
//
// When the budget is spent it fails at once with a RateLimitError that says
// when a slot frees up, rather than waiting. Background writes stop
// InteractiveReserve slots earlier than interactive ones.
func (p *Pacer) Wait(ctx context.Context, interactive bool) (time.Time, error) {
	p.mu.Lock()
	now := p.now()
	for len(p.sent) > 0 && now.Sub(p.sent[0]) >= time.Hour {
		p.sent = p.sent[1:]
	}
	limit := p.budget
	if !interactive {
		limit -= p.reserve
	}
	if p.budget > 0 && len(p.sent) >= limit {
		retryAt := now.Add(time.Minute)
		if over := len(p.sent) - limit; over < len(p.sent) {
			retryAt = p.sent[over].Add(time.Hour)
		}
		p.mu.Unlock()
		return time.Time{}, &RateLimitError{APIError: APIError{Path: "write budget"}, RetryAt: retryAt}
	}
	slot := now
	if p.next.After(slot) {
		slot = p.next
	}
	p.next = slot.Add(p.gap)
	p.sent = append(p.sent, slot)
	p.mu.Unlock()

	if d := slot.Sub(p.now()); d > 0 {
		t := time.NewTimer(d)
		defer t.Stop()
		select {
		case <-ctx.Done():
			p.Release(slot)
			return time.Time{}, ctx.Err()
		case <-t.C:
		}
	}
	return slot, nil
}

// Release gives back a slot whose write never went out.
func (p *Pacer) Release(slot time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for i, t := range p.sent {
		if t.Equal(slot) {
			p.sent = append(p.sent[:i], p.sent[i+1:]...)
			return
		}
	}
}

// LowQuota is the share of a rate limit below which background work (the
// reconcile sweep and the jobs it queued) stops until the reset.
const LowQuota = 0.1
