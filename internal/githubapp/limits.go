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
	// Outage marks a call held back while GitHub keeps failing, rather than
	// one GitHub limited; see Limits.Held. Callers defer it the same way,
	// without the rate limit alert: the hold raises its own.
	Outage bool
}

func (e *RateLimitError) Error() string {
	if e.Outage {
		return e.APIError.Error() + " (held: GitHub keeps failing)"
	}
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

// Held reports whether err is a call held back while GitHub keeps failing.
func Held(err error) bool {
	var rl *RateLimitError
	return errors.As(err, &rl) && rl.Outage
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

	// failures counts calls in a row that got a server error or no answer,
	// within holdWindow of the first. After holdAfter of them every call is
	// held back until heldUntil, so a GitHub outage is not met with a retry
	// from every pull request. Once a hold ends, one call at a time goes out
	// as the probe until probeUntil: an answer ends the outage, another
	// failure holds again for twice as long.
	failures     int
	firstFailure time.Time
	heldUntil    time.Time
	probeUntil   time.Time
	hold         time.Duration
	onHold       func(status int)
	onRecover    func()
}

// The outage hold: after holdAfter failed calls in a row within holdWindow,
// a minute, then twice as long each time the probe fails, up to holdMax. A
// probe that never reports back frees its place after probeTimeout.
const (
	holdAfter    = 5
	holdWindow   = time.Minute
	holdMin      = time.Minute
	holdMax      = 15 * time.Minute
	probeTimeout = 2 * callTimeout
)

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

// OnOutage sets what to do when a hold starts, with the status of the last
// failure (0 for no answer), and when a call gets an answer again after one.
// Both run outside the lock and must not block.
func (l *Limits) OnOutage(hold func(status int), recovered func()) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.onHold, l.onRecover = hold, recovered
}

// answered notes how GitHub answered a call: status, or 0 for no answer.
// A server error or no answer counts towards a hold, anything else ends one.
func (l *Limits) answered(status int) {
	failed := status == 0 || status >= 500
	l.mu.Lock()
	var hold func(int)
	var recovered func()
	now := l.now()
	l.probeUntil = time.Time{}
	if failed {
		// Failures spread out over time are not an outage: count anew. In
		// an outage every failure counts, the probe's included.
		if l.hold == 0 && (l.failures == 0 || now.Sub(l.firstFailure) > holdWindow) {
			l.failures, l.firstFailure = 0, now
		}
		l.failures++
		if (l.hold > 0 || l.failures >= holdAfter) && !l.heldUntil.After(now) {
			l.hold = min(max(2*l.hold, holdMin), holdMax)
			l.heldUntil = now.Add(l.hold)
			hold = l.onHold
		}
	} else {
		if l.hold > 0 {
			recovered = l.onRecover
		}
		l.failures, l.hold = 0, 0
	}
	l.mu.Unlock()
	if hold != nil {
		hold(status)
	}
	if recovered != nil {
		recovered()
	}
}

// failed notes a call that failed before or without an answer GitHub's
// limits saw, such as minting the installation token: no answer or a server
// error counts towards a hold. A call cut short by its caller says nothing
// about GitHub.
func (l *Limits) failed(err error) {
	var terr *transportError
	switch {
	case errors.As(err, &terr) && !errors.Is(err, context.Canceled):
		l.answered(0)
	case StatusOf(err) >= 500:
		l.answered(StatusOf(err))
	}
}

// Held reports whether a call must be held back because GitHub keeps
// failing, and until when. After a hold it lets one call through as the
// probe and holds the rest until that one reports back.
func (l *Limits) Held() (time.Time, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if l.heldUntil.After(now) {
		return l.heldUntil, true
	}
	if l.hold > 0 {
		if l.probeUntil.After(now) {
			return l.probeUntil, true
		}
		l.probeUntil = now.Add(probeTimeout)
	}
	return time.Time{}, false
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
