package store

import (
	"context"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"sort"
	"strings"
	"sync"

	"github.com/rotki/cla/internal/githubapp"
)

// CLAText is the agreement at one gist revision, rendered to HTML.
type CLAText struct {
	Revision string
	URL      string
	HTML     template.HTML
}

// Agreement fetches and renders the pinned CLA revision once per revision.
// Pages only read the cache; startup and the sweep fill it, and a page that
// finds it empty starts a background load, so a visitor never waits on
// GitHub.
type Agreement struct {
	c *githubapp.Client

	mu    sync.Mutex
	cache map[string]CLAText
}

func NewAgreement(c *githubapp.Client) *Agreement {
	return &Agreement{c: c, cache: map[string]CLAText{}}
}

// Cached returns the CLA at the revision pinned in cfg, if it was loaded.
func (a *Agreement) Cached(cfg RepoConfig) (CLAText, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	text, ok := a.cache[cfg.CLAGist+"/"+cfg.CLARevision]
	return text, ok
}

// Warm loads and renders the pinned revision unless it is cached already.
func (a *Agreement) Warm(ctx context.Context, cfg RepoConfig) error {
	if cfg.CLAGist == "" || cfg.CLARevision == "" {
		return errors.New("cla_gist and cla_revision must be set in config.json")
	}
	if _, ok := a.Cached(cfg); ok {
		return nil
	}
	_, err := a.load(ctx, cfg)
	return err
}

func (a *Agreement) load(ctx context.Context, cfg RepoConfig) (CLAText, error) {
	key := cfg.CLAGist + "/" + cfg.CLARevision

	var gist struct {
		Files map[string]struct {
			Content string `json:"content"`
		} `json:"files"`
	}
	if _, err := a.c.Do(ctx, http.MethodGet, "/gists/"+key, nil, &gist); err != nil {
		return CLAText{}, err
	}
	names := make([]string, 0, len(gist.Files))
	for name := range gist.Files {
		if strings.HasSuffix(strings.ToLower(name), ".md") {
			names = append(names, name)
		}
	}
	if len(names) == 0 {
		return CLAText{}, fmt.Errorf("gist %s has no markdown file", key)
	}
	sort.Strings(names)

	// GitHub's renderer sanitises its output, which is why it is safe to
	// mark as trusted HTML.
	html, err := a.c.DoRaw(ctx, http.MethodPost, "/markdown", map[string]string{
		"text": gist.Files[names[0]].Content,
		"mode": "markdown",
	})
	if err != nil {
		return CLAText{}, err
	}

	text := CLAText{
		Revision: cfg.CLARevision,
		URL:      fmt.Sprintf("https://gist.github.com/%s/%s", cfg.CLAGist, cfg.CLARevision),
		HTML:     template.HTML(html), //nolint:gosec // sanitised by GitHub's markdown API
	}
	a.mu.Lock()
	a.cache[key] = text
	a.mu.Unlock()
	return text, nil
}
