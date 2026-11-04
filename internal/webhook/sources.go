package webhook

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"github.com/rotki/cla/internal/githubapp"
)

// Sources holds the address ranges GitHub sends webhooks from, as its /meta
// endpoint lists them under "hooks". A delivery with a bad signature from
// inside them points at a webhook secret that no longer matches the App's;
// from anywhere else it is someone probing the endpoint, not worth an alert.
//
// GitHub sets no lifetime for the list and changes it now and then, asking
// those who use it to keep watching /meta. Run refreshes it daily, keeps the
// last good list when a refresh fails, and refreshes early when a bad
// signature arrives from outside it, in case GitHub added a range since.
//
// A delivery with a valid signature from outside the list shows the address
// cannot be told apart here: a CDN or a proxy that sets X-Real-Ip to its own
// address sits in front, or GitHub added a range. Until the next refresh
// every bad signature then alerts again, so a broken secret is never hidden.
type Sources struct {
	mu       sync.RWMutex
	prefixes []netip.Prefix
	// blind is set by a valid delivery from outside the list.
	blind bool
	// stale asks Run for an early refresh, which follows the last one by
	// minAge at the soonest.
	stale  chan struct{}
	minAge time.Duration
}

func NewSources() *Sources {
	return &Sources{stale: make(chan struct{}, 1), minAge: sourcesMinAge}
}

// Refresh loads the ranges from GitHub's /meta endpoint. On failure the
// ranges loaded before are kept.
func (s *Sources) Refresh(ctx context.Context, c *githubapp.Client) error {
	var meta struct {
		Hooks []string `json:"hooks"`
	}
	if _, err := c.Do(ctx, http.MethodGet, "/meta", nil, &meta); err != nil {
		return err
	}
	var prefixes []netip.Prefix
	for _, h := range meta.Hooks {
		if p, err := netip.ParsePrefix(h); err == nil {
			prefixes = append(prefixes, p)
		}
	}
	if len(prefixes) == 0 {
		return errors.New("GitHub's /meta lists no webhook ranges")
	}
	s.mu.Lock()
	s.prefixes = prefixes
	s.blind = false
	s.mu.Unlock()
	return nil
}

// sourcesRetry is how soon a failed refresh is tried again; sourcesMinAge how
// long after the last refresh an early one may follow, so anyone posting junk
// from elsewhere cannot make the service call /meta more than once an hour.
const (
	sourcesRetry  = 15 * time.Minute
	sourcesMinAge = time.Hour
)

// Run refreshes the ranges now and then every interval until ctx is done. An
// early refresh asked for too soon after the last one is put off until it may
// follow, not dropped: nothing may ask again.
func (s *Sources) Run(ctx context.Context, c *githubapp.Client, interval time.Duration) {
	for {
		wait := interval
		last := time.Now()
		if err := s.Refresh(ctx, c); err != nil {
			if ctx.Err() != nil {
				return
			}
			slog.Warn("loading GitHub's webhook ranges failed", "error", err)
			wait = sourcesRetry
		}
		next := last.Add(wait)
		timer := time.NewTimer(wait)
		for waiting := true; waiting; {
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
				waiting = false
			case <-s.stale:
				if early := last.Add(s.minAge); early.Before(next) {
					next = early
					timer.Reset(time.Until(next))
				}
			}
		}
		timer.Stop()
	}
}

// markStale asks Run for an early refresh without waiting on it.
func (s *Sources) markStale() {
	if s == nil {
		return
	}
	select {
	case s.stale <- struct{}{}:
	default:
	}
}

// fromGitHub reports whether a bad signature on r is worth an alert: r comes
// from GitHub's webhook ranges, or that cannot be known. Until the ranges are
// loaded, while they are blind, or when the address does not parse, every
// request counts as GitHub's, so a secret that does not match is never missed.
func (s *Sources) fromGitHub(r *http.Request) bool {
	if s == nil {
		return true
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	in, known := s.contains(r)
	return in || !known || s.blind
}

// sawValid notes a delivery with a valid signature. From outside the ranges
// it makes them blind until the next refresh, and asks for that early.
func (s *Sources) sawValid(r *http.Request) {
	if s == nil {
		return
	}
	// Most deliveries change nothing: look under the read lock first.
	s.mu.RLock()
	in, known := s.contains(r)
	outside := known && !in && !s.blind
	s.mu.RUnlock()
	if !outside {
		return
	}
	s.mu.Lock()
	in, known = s.contains(r)
	newly := known && !in && !s.blind
	if newly {
		s.blind = true
	}
	s.mu.Unlock()
	if newly {
		slog.Warn("a valid webhook came from outside GitHub's ranges: alerting on every bad signature until the ranges refresh; check that the proxy sets X-Real-Ip to the client's address")
		s.markStale()
	}
}

// contains reports whether r's client is in the ranges, and whether that is
// known: false when the ranges are not loaded or the address does not parse.
// The client is X-Real-Ip, which the proxy in front sets, or the peer
// address, as in the access log. Called with s.mu held.
func (s *Sources) contains(r *http.Request) (in, known bool) {
	if len(s.prefixes) == 0 {
		return false, false
	}
	remote := r.Header.Get("X-Real-Ip")
	if remote == "" {
		remote, _, _ = net.SplitHostPort(r.RemoteAddr)
	}
	addr, err := netip.ParseAddr(remote)
	if err != nil {
		return false, false
	}
	addr = addr.Unmap()
	for _, p := range s.prefixes {
		if p.Contains(addr) {
			return true, true
		}
	}
	return false, true
}
