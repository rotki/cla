package check

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/rotki/cla/internal/githubapp"
	"github.com/rotki/cla/internal/org"
	"github.com/rotki/cla/internal/store"
)

// Ref names a pull request in the org.
type Ref struct {
	Repo   string
	Number int
}

func (r Ref) String() string {
	return fmt.Sprintf("%s#%d", r.Repo, r.Number)
}

type Checker struct {
	gh         *githubapp.Client
	store      *store.Store
	dir        *org.Directory
	owner      string
	context    string
	baseURL    string
	botLogin   func() string
	noComments bool

	mu       sync.Mutex
	blocked  map[int64]map[Ref]bool
	blocks   map[Ref][]int64
	comments map[Ref]comment
	last     map[Ref]lastCheck
}

// lastCheck is what was last reported for a pull request, with the authors it
// was computed from. A re-check at the same head commit whose fingerprint is
// unchanged cannot change the result, so it is skipped: the sweep decides
// that from memory alone, without a single request.
type lastCheck struct {
	headSHA string
	inputs  string
	status  Status
	authors []Author
	botPR   bool
	// at is when it was reported; see Prune.
	at time.Time
}

// errStopPaging ends a pagination early once the wanted item is found.
var errStopPaging = errors.New("stop paging")

// ErrNotReady is returned while the signatures have not been loaded yet; the
// check is retried shortly.
var ErrNotReady = errors.New("signatures not loaded yet")

type comment struct {
	id   int64
	body string
}

type Options struct {
	Owner         string
	StatusContext string
	BaseURL       string
	// BotLogin returns "<app slug>[bot]", the author of our comments.
	BotLogin func() string
	// NoComments leaves pull requests without the sticky comment, so only
	// the status reports: for a shadow run next to another CLA tool, whose
	// own comment already asks people to sign.
	NoComments bool
}

func NewChecker(gh *githubapp.Client, st *store.Store, dir *org.Directory, opts Options) *Checker {
	return &Checker{
		gh:         gh,
		store:      st,
		dir:        dir,
		owner:      opts.Owner,
		context:    opts.StatusContext,
		baseURL:    opts.BaseURL,
		botLogin:   opts.BotLogin,
		noComments: opts.NoComments,
		blocked:    map[int64]map[Ref]bool{},
		blocks:     map[Ref][]int64{},
		comments:   map[Ref]comment{},
		last:       map[Ref]lastCheck{},
	}
}

// fingerprint covers everything a result depends on besides the commits:
// the config, the exempt team, and the standing of this pull request's own
// authors. A signature by someone unrelated leaves it unchanged, so it does
// not send every pending pull request back to GitHub.
func (c *Checker) fingerprint(authors []Author, botPR bool) string {
	cfg := c.store.Config()
	var b strings.Builder
	fmt.Fprintf(&b, "%s|%s|%t", c.store.ConfigVersion(), c.dir.Version(cfg.ExemptTeam), botPR)
	for _, a := range authors {
		if a.Linked() {
			fmt.Fprintf(&b, "|%d:%d", a.ID, c.store.StandingOf(a.ID))
		} else {
			// Unlinked authors fail the check, so a change in who they are
			// changes the result even at the same head commit: a pull
			// request moved to another base can gain one.
			fmt.Fprintf(&b, "|u:%q", a.Name)
		}
	}
	return b.String()
}

// UpToDate reports whether ref was already checked at headSHA and nothing it
// depends on has changed since, so the reconcile sweep can leave it alone.
func (c *Checker) UpToDate(ref Ref, headSHA string) bool {
	c.mu.Lock()
	l, ok := c.last[ref]
	c.mu.Unlock()
	return ok && l.inputs != "" && l.headSHA == headSHA && l.inputs == c.fingerprint(l.authors, l.botPR)
}

// RefreshTeam fetches the exempt team again if its cache expired. The
// sweep calls it before deciding what is up to date: only a fetch changes
// the team's version in the fingerprint, and nothing else fetches for a
// pull request the sweep leaves alone, so without it a blocked author who
// joined the team would stay blocked.
func (c *Checker) RefreshTeam(ctx context.Context) error {
	_, err := c.dir.TeamMembers(ctx, c.store.Config().ExemptTeam)
	return err
}

// Context is the commit status name this checker reports under.
func (c *Checker) Context() string {
	return c.context
}

// Skipped reports whether a repo is never checked.
func (c *Checker) Skipped(repo string) bool {
	for _, r := range c.store.Config().ExcludedRepos {
		if strings.EqualFold(r, repo) {
			return true
		}
	}
	return false
}

// Hint is what the caller already knows about a pull request.
type Hint struct {
	// Force re-checks and re-reports even when nothing seems to have
	// changed, for a pull request whose status is missing on GitHub.
	Force bool
	// Known is the status GitHub shows on a head commit, when the caller has
	// just read it. A computed status equal to it is not sent again, which
	// matters after a restart, when nothing is remembered. It is ignored
	// when the head moved since: the new head has no status yet.
	Known *KnownStatus
}

// KnownStatus is a status read from GitHub with the commit it is on.
type KnownStatus struct {
	Status
	SHA string
}

// On is the status as read on commit sha; nil stays nil.
func (s *Status) On(sha string) *KnownStatus {
	if s == nil {
		return nil
	}
	return &KnownStatus{Status: *s, SHA: sha}
}

// CheckPR evaluates one pull request and reports the result. Unless forced,
// a pull request already reported at the same head with the same inputs is
// skipped, and a status equal to the last one sent is not sent again.
func (c *Checker) CheckPR(ctx context.Context, ref Ref, hint Hint) error {
	if !c.store.Ready() {
		return ErrNotReady
	}
	if c.Skipped(ref.Repo) {
		return nil
	}
	pr, err := fetchPR(ctx, c.gh, c.owner, ref.Repo, ref.Number)
	if err != nil {
		return err
	}
	if !pr.Open || pr.HeadSHA == "" {
		c.Forget(ref)
		return nil
	}

	cfg := c.store.Config()
	team, err := c.dir.TeamMembers(ctx, cfg.ExemptTeam)
	if err != nil {
		return err
	}
	inputs := c.fingerprint(pr.Authors, pr.OpenedByBot)
	c.mu.Lock()
	prev := c.last[ref]
	c.mu.Unlock()
	if hint.Force {
		prev = lastCheck{}
	} else if prev.headSHA == "" && hint.Known != nil && hint.Known.SHA == pr.HeadSHA {
		prev = lastCheck{headSHA: pr.HeadSHA, status: hint.Known.Status}
	}
	if prev.headSHA == pr.HeadSHA && prev.inputs == inputs {
		return nil
	}

	res := Evaluate(pr.Authors, NewRules(cfg.Allowlist, team, pr.OpenedByBot), c.store.StandingOf)
	signURL := SignURL(c.baseURL, c.owner, ref.Repo, ref.Number)
	status := StatusFor(res)
	if prev.headSHA != pr.HeadSHA || prev.status != status {
		if err := c.setStatus(ctx, ref.Repo, pr.HeadSHA, status, signURL); err != nil {
			return err
		}
		// Remember the status at once, so a retry after a failed comment
		// write does not send it again.
		c.mu.Lock()
		c.last[ref] = lastCheck{headSHA: pr.HeadSHA, status: status, at: time.Now()}
		c.mu.Unlock()
	}
	if !c.noComments {
		body, needed := Comment(res, signURL, c.baseURL+"/cla")
		if err := c.upsertComment(ctx, ref, body, needed); err != nil {
			return err
		}
	}
	c.setBlocking(ref, res.Blocking())
	c.mu.Lock()
	c.last[ref] = lastCheck{headSHA: pr.HeadSHA, inputs: inputs, status: status, authors: pr.Authors, botPR: pr.OpenedByBot, at: time.Now()}
	c.mu.Unlock()
	return nil
}

// PassMergeGroup greenlights a merge queue commit. Each pull request in it was
// checked already, as cla-assistant does.
func (c *Checker) PassMergeGroup(ctx context.Context, repo, sha string) error {
	if c.Skipped(repo) {
		return nil
	}
	return c.setStatus(ctx, repo, sha, Status{"success", "Checked on the pull request."}, "")
}

func (c *Checker) setStatus(ctx context.Context, repo, sha string, s Status, targetURL string) error {
	body := map[string]string{
		"state":       s.State,
		"description": s.Description,
		"context":     c.context,
	}
	if targetURL != "" {
		body["target_url"] = targetURL
	}
	_, err := c.gh.Do(ctx, http.MethodPost, fmt.Sprintf("/repos/%s/%s/statuses/%s", c.owner, repo, sha), body, nil)
	return err
}

func (c *Checker) upsertComment(ctx context.Context, ref Ref, body string, needed bool) error {
	existing, err := c.findComment(ctx, ref)
	if err != nil {
		return err
	}
	if existing.id == 0 {
		if !needed {
			return nil
		}
		var created struct {
			ID int64 `json:"id"`
		}
		path := fmt.Sprintf("/repos/%s/%s/issues/%d/comments", c.owner, ref.Repo, ref.Number)
		if _, err := c.gh.Do(ctx, http.MethodPost, path, map[string]string{"body": body}, &created); err != nil {
			return err
		}
		c.rememberComment(ref, comment{id: created.ID, body: body})
		return nil
	}
	if existing.body == body {
		return nil
	}
	path := fmt.Sprintf("/repos/%s/%s/issues/comments/%d", c.owner, ref.Repo, existing.id)
	_, err = c.gh.Do(ctx, http.MethodPatch, path, map[string]string{"body": body}, nil)
	if githubapp.IsStatus(err, http.StatusNotFound) {
		// Someone deleted it; post a fresh one next time.
		c.forgetComment(ref)
		return nil
	}
	if err != nil {
		return err
	}
	c.rememberComment(ref, comment{id: existing.id, body: body})
	return nil
}

func (c *Checker) findComment(ctx context.Context, ref Ref) (comment, error) {
	c.mu.Lock()
	cached, ok := c.comments[ref]
	c.mu.Unlock()
	if ok {
		return cached, nil
	}

	// No comment found is cached too: the bot is the only author of its
	// comment, so it stays absent until this checker posts one.
	var found comment
	bot := c.botLogin()
	path := fmt.Sprintf("/repos/%s/%s/issues/%d/comments?per_page=100", c.owner, ref.Repo, ref.Number)
	err := githubapp.Paginate(ctx, c.gh, path, func(page []struct {
		ID   int64  `json:"id"`
		Body string `json:"body"`
		User struct {
			Login string `json:"login"`
		} `json:"user"`
	}) error {
		for _, cm := range page {
			if cm.User.Login == bot && strings.HasPrefix(cm.Body, Marker) {
				found = comment{id: cm.ID, body: cm.Body}
				return errStopPaging
			}
		}
		return nil
	})
	if err != nil && !errors.Is(err, errStopPaging) {
		return found, err
	}
	c.rememberComment(ref, found)
	return found, nil
}

func (c *Checker) rememberComment(ref Ref, cm comment) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.comments[ref] = cm
}

func (c *Checker) forgetComment(ref Ref) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.comments, ref)
}

// setBlocking records which accounts hold up a pull request, so a new
// signature re-checks exactly those pull requests.
func (c *Checker) setBlocking(ref Ref, ids []int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, id := range c.blocks[ref] {
		delete(c.blocked[id], ref)
		if len(c.blocked[id]) == 0 {
			delete(c.blocked, id)
		}
	}
	if len(ids) == 0 {
		delete(c.blocks, ref)
		return
	}
	c.blocks[ref] = ids
	for _, id := range ids {
		if c.blocked[id] == nil {
			c.blocked[id] = map[Ref]bool{}
		}
		c.blocked[id][ref] = true
	}
}

// Forget drops everything remembered about a pull request, once it is closed
// or no longer open.
func (c *Checker) Forget(ref Ref) {
	c.setBlocking(ref, nil)
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.last, ref)
	delete(c.comments, ref)
}

// ForgetResults drops every remembered result, so the next check of each
// pull request evaluates it again. Cached comments are kept.
func (c *Checker) ForgetResults() {
	c.mu.Lock()
	defer c.mu.Unlock()
	clear(c.last)
}

// Prune forgets every pull request not in open, so memory follows the open
// pull requests rather than growing forever. One checked after since is
// kept: GitHub's search lags behind events, so a pull request opened just
// before the sweep can be missing from open.
func (c *Checker) Prune(open map[Ref]bool, since time.Time) {
	c.mu.Lock()
	gone := func(ref Ref) bool {
		return !open[ref] && !c.last[ref].at.After(since)
	}
	var stale []Ref
	for ref := range c.last {
		if gone(ref) {
			stale = append(stale, ref)
		}
	}
	for ref := range c.comments {
		if gone(ref) {
			stale = append(stale, ref)
		}
	}
	for ref := range c.blocks {
		if gone(ref) {
			stale = append(stale, ref)
		}
	}
	c.mu.Unlock()
	for _, ref := range stale {
		c.Forget(ref)
	}
}

// BlockedBy returns the pull requests waiting on an account.
func (c *Checker) BlockedBy(id int64) []Ref {
	c.mu.Lock()
	defer c.mu.Unlock()
	refs := make([]Ref, 0, len(c.blocked[id]))
	for ref := range c.blocked[id] {
		refs = append(refs, ref)
	}
	return refs
}
