package org

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/rotki/cla/internal/fakegh"
	"github.com/rotki/cla/internal/githubapp"
)

func TestIsAdminIsCachedBriefly(t *testing.T) {
	ctx := context.Background()
	gh := fakegh.New()
	t.Cleanup(gh.Close)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	app := githubapp.New(1, key, gh.URL)
	if err := app.Init(ctx, "rotki"); err != nil {
		t.Fatal(err)
	}
	d := New(app.Client(githubapp.Scope{}), "rotki")
	now := time.Unix(1_000_000, 0)
	d.now = func() time.Time { return now }

	ask := func(login string) bool {
		t.Helper()
		admin, err := d.IsAdmin(ctx, login)
		if err != nil {
			t.Fatal(err)
		}
		return admin
	}

	gh.Admins["boss"] = true
	if !ask("boss") {
		t.Fatal("an admin was refused")
	}
	gh.Mu.Lock()
	delete(gh.Admins, "boss")
	gh.Mu.Unlock()
	if !ask("boss") {
		t.Fatal("the answer was not cached")
	}
	now = now.Add(adminTTL)
	if ask("boss") {
		t.Fatal("a removed admin kept access after a minute")
	}

	// A no is kept longer: a loop on /admin costs one call per ten minutes.
	gh.Admins["boss"] = true
	now = now.Add(adminTTL)
	if ask("boss") {
		t.Fatal("a no was not cached")
	}
	now = now.Add(notAdminTTL)
	if !ask("boss") {
		t.Fatal("a new admin was refused after ten minutes")
	}
}
