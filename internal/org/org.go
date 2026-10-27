// Package org answers membership questions about the GitHub org: who is an
// admin (for /admin) and who is in the exempt team (for checks).
package org

import (
	"context"
	"fmt"
	"maps"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/rotki/cla/internal/githubapp"
)

type Directory struct {
	c   *githubapp.Client
	org string
	ttl time.Duration
	now func() time.Time

	// mu guards the cache below and is never held across a GitHub call;
	// fetchMu lets one caller at a time refresh it.
	mu        sync.Mutex
	fetchMu   sync.Mutex
	team      string
	members   map[string]bool
	fetchedAt time.Time
	version   int
	admins    map[string]adminAnswer
}

type adminAnswer struct {
	admin bool
	until time.Time
}

// How long an IsAdmin answer is kept. Every logged-in account can ask, so
// without a cache a loop on /admin would spend the quota the checks need.
// A yes is kept briefly, so a removed admin loses access within a minute.
const (
	adminTTL    = time.Minute
	notAdminTTL = 10 * time.Minute
	maxAdmins   = 1000
)

func New(c *githubapp.Client, org string) *Directory {
	// The team changes rarely; refreshing it once per sweep interval is enough.
	return &Directory{c: c, org: org, ttl: 30 * time.Minute, now: time.Now}
}

// IsAdmin reports whether login is an active admin of the org.
func (d *Directory) IsAdmin(ctx context.Context, login string) (bool, error) {
	key := strings.ToLower(login)
	d.mu.Lock()
	a, ok := d.admins[key]
	d.mu.Unlock()
	if ok && d.now().Before(a.until) {
		return a.admin, nil
	}
	admin, err := d.fetchAdmin(ctx, login)
	if err != nil {
		return false, err
	}
	ttl := notAdminTTL
	if admin {
		ttl = adminTTL
	}
	now := d.now()
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.admins == nil || len(d.admins) >= maxAdmins {
		d.admins = map[string]adminAnswer{}
	}
	d.admins[key] = adminAnswer{admin: admin, until: now.Add(ttl)}
	return admin, nil
}

// Forget drops the cached IsAdmin answer for login.
func (d *Directory) Forget(login string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.admins, strings.ToLower(login))
}

func (d *Directory) fetchAdmin(ctx context.Context, login string) (bool, error) {
	var m struct {
		State string `json:"state"`
		Role  string `json:"role"`
	}
	_, err := d.c.Do(ctx, http.MethodGet, fmt.Sprintf("/orgs/%s/memberships/%s", d.org, login), nil, &m)
	if githubapp.IsStatus(err, http.StatusNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return m.State == "active" && m.Role == "admin", nil
}

// TeamMembers returns the lower-cased logins in the team, cached for half
// an hour. An empty slug means no team is exempt.
//
// One caller refreshes at a time, without holding the cache lock across the
// calls; meanwhile others get the stale copy rather than waiting on GitHub.
func (d *Directory) TeamMembers(ctx context.Context, slug string) (map[string]bool, error) {
	if slug == "" {
		return map[string]bool{}, nil
	}
	d.mu.Lock()
	cached, fresh := d.members, d.team == slug && d.members != nil && d.now().Sub(d.fetchedAt) < d.ttl
	stale := d.team == slug && d.members != nil
	d.mu.Unlock()
	if fresh {
		return cached, nil
	}

	if !d.fetchMu.TryLock() {
		if stale {
			return cached, nil
		}
		d.fetchMu.Lock()
	}
	defer d.fetchMu.Unlock()

	d.mu.Lock()
	if d.team == slug && d.members != nil && d.now().Sub(d.fetchedAt) < d.ttl {
		cached = d.members
		d.mu.Unlock()
		return cached, nil // refreshed while we waited
	}
	d.mu.Unlock()

	members := map[string]bool{}
	path := fmt.Sprintf("/orgs/%s/teams/%s/members?per_page=100", d.org, slug)
	err := githubapp.Paginate(ctx, d.c, path, func(page []struct {
		Login string `json:"login"`
	}) error {
		for _, m := range page {
			members[strings.ToLower(m.Login)] = true
		}
		return nil
	})
	if err != nil {
		if stale {
			return cached, nil
		}
		return nil, err
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	if d.team != slug || !maps.Equal(d.members, members) {
		d.version++
	}
	d.team = slug
	d.members = members
	d.fetchedAt = d.now()
	return members, nil
}

// Version changes whenever the exempt team's membership does, so results
// computed with an older membership are known to be stale.
func (d *Directory) Version(slug string) string {
	d.mu.Lock()
	defer d.mu.Unlock()
	if slug == "" {
		return "none"
	}
	return fmt.Sprintf("%s:%d", d.team, d.version)
}
