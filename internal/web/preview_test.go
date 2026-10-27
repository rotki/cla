//go:build preview

package web

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/rotki/cla/internal/store"
)

// TestPreview serves the site against the fake GitHub until interrupted, for
// working on the pages: make preview. The fake approves every login as
// @newbie, who is also an org admin. It prints where the data directory is,
// so the records and the audit log can be inspected, and every commit status
// and bot comment the service posts to the fake pull request.
func TestPreview(t *testing.T) {
	h := newHarness(t)
	h.gh.Admins["newbie"] = true
	// rotki's own logo, as on cla.rotki.com.
	if logo, err := os.ReadFile("../../examples/logo.svg"); err == nil {
		writeFile(t, h.data, store.LogoSVG, string(logo))
		if err := h.store.Refresh(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	fmt.Printf("preview at %s/sign?owner=rotki&repo=rotki&pr=1\n", h.site.URL)
	fmt.Printf("admin page at %s/admin\n", h.site.URL)
	fmt.Printf("data directory: %s\n", h.data)

	statuses, comments := 0, map[int64]string{}
	for range time.Tick(time.Second) {
		h.gh.Mu.Lock()
		for _, s := range h.gh.Statuses[statuses:] {
			fmt.Printf("status %s on %s: %s (%s)\n", s.State, s.SHA, s.Description, s.Context)
		}
		statuses = len(h.gh.Statuses)
		for _, c := range h.gh.Comments {
			if comments[c.ID] != c.Body {
				comments[c.ID] = c.Body
				fmt.Printf("comment on %s#%d:\n%s\n\n", c.Repo, c.Number, c.Body)
			}
		}
		h.gh.Mu.Unlock()
	}
}
