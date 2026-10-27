package web

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"filippo.io/age"

	"github.com/rotki/cla/internal/alert"
	"github.com/rotki/cla/internal/check"
	"github.com/rotki/cla/internal/fakegh"
	"github.com/rotki/cla/internal/githubapp"
	"github.com/rotki/cla/internal/org"
	"github.com/rotki/cla/internal/reconcile"
	"github.com/rotki/cla/internal/seal"
	"github.com/rotki/cla/internal/site"
	"github.com/rotki/cla/internal/store"
)

type harness struct {
	api      *githubapp.Client
	store    *store.Store
	dir      *org.Directory
	app      *githubapp.App
	srv      *Server
	gh       *fakegh.Server
	site     *httptest.Server
	client   *http.Client
	checker  *check.Checker
	identity *age.X25519Identity
	data     string
}

// file reads a file from the data directory, "" when absent.
func (h *harness) file(rel string) string {
	data, _ := os.ReadFile(filepath.Join(h.data, filepath.FromSlash(rel)))
	return string(data)
}

// writeFile writes a file into a data directory, as an admin would by hand.
func writeFile(t *testing.T, dir, rel, content string) {
	t.Helper()
	path := filepath.Join(dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o640); err != nil {
		t.Fatal(err)
	}
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	gh := fakegh.New()
	t.Cleanup(gh.Close)
	data := t.TempDir()
	writeFile(t, data, store.ConfigFile, `{"cla_gist":"gist1","cla_revision":"rev1","exempt_team":"core"}`)
	writeFile(t, data, store.Grandfathered, `[100]`)
	gh.Team = []string{"Maintainer"}
	gh.User.ID, gh.User.Login, gh.User.Name = 400, "newbie", "New Contributor"
	gh.Emails = []string{"newbie@example.com", "work@example.com"}
	gh.PRs["rotki#1"] = fakegh.PR{Open: true, HeadSHA: "head1", Commits: []fakegh.Commit{
		{AuthorName: "Old Timer", AuthorID: 100, AuthorLogin: "oldtimer"},
		{AuthorName: "Newbie", AuthorID: 400, AuthorLogin: "newbie"},
		{AuthorName: "Maintainer", AuthorID: 500, AuthorLogin: "maintainer"},
	}}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	app := githubapp.New(1, key, gh.URL)
	app.SetWriteGap(0)
	if err := app.Init(ctx, "rotki"); err != nil {
		t.Fatal(err)
	}
	client := app.Client(githubapp.Scope{})
	identity, _ := age.GenerateX25519Identity()
	sealer, _ := seal.New(identity.Recipient().String(), "test")
	alerts := alert.New("")
	st := store.New(data)
	if err := st.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	dir := org.New(client, "rotki")
	agreement := store.NewAgreement(githubapp.NewPublicClient(gh.URL))
	if err := agreement.Warm(ctx, st.Config()); err != nil {
		t.Fatal(err)
	}

	ts := httptest.NewUnstartedServer(nil)
	baseURL := "http://" + ts.Listener.Addr().String()
	checker := check.NewChecker(client, st, dir, check.Options{
		Owner: "rotki", StatusContext: "license/cla", BaseURL: baseURL,
		BotLogin: func() string { return app.Slug() + "[bot]" },
	})
	queue := check.NewQueue(checker, alerts, app.Limits, 100)
	rechecker := reconcile.New(client, st, agreement, checker, queue, alerts, app.Limits, "rotki")
	go queue.Run(ctx, 2)

	srv, err := New(Deps{
		App: app,
		OAuth: &githubapp.OAuth{
			ClientID: "Iv1.test", ClientSecret: "secret", RedirectURL: baseURL + "/oauth/callback", GitHubURL: gh.URL, APIURL: gh.URL,
		},
		Store:      st,
		Agreement:  agreement,
		Directory:  dir,
		Sealer:     sealer,
		Checker:    checker,
		Queue:      queue,
		Alerts:     alerts,
		Limits:     app.Limits,
		Rechecker:  rechecker,
		Org:        "rotki",
		SessionKey: []byte(strings.Repeat("k", 32)),
	})
	if err != nil {
		t.Fatal(err)
	}
	ts.Config.Handler = srv.Handler(http.NotFoundHandler())
	ts.Start()
	t.Cleanup(ts.Close)

	jar, _ := cookiejar.New(nil)
	return &harness{
		srv:   srv,
		api:   client,
		store: st,
		data:  data,
		dir:   dir,
		app:   app,
		gh:    gh,
		site:  ts,
		client: &http.Client{
			Jar:           jar,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		checker:  checker,
		identity: identity,
	}
}

func (h *harness) get(t *testing.T, path string) (resp *http.Response, body string) {
	t.Helper()
	resp, err := h.client.Get(h.site.URL + path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, _ := io.ReadAll(resp.Body)
	return resp, string(data)
}

func (h *harness) post(t *testing.T, path string, form url.Values) (resp *http.Response, body string) {
	t.Helper()
	resp, err := h.client.PostForm(h.site.URL+path, form)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, _ := io.ReadAll(resp.Body)
	return resp, string(data)
}

// login walks the OAuth flow against the fake GitHub.
func (h *harness) login(t *testing.T, returnTo string) {
	t.Helper()
	resp, _ := h.get(t, "/login?return="+url.QueryEscape(returnTo))
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("login: %d", resp.StatusCode)
	}
	authorize, _ := url.Parse(resp.Header.Get("Location"))
	if authorize.Query().Get("code_challenge") == "" {
		t.Fatal("no PKCE challenge in the authorize URL")
	}
	state := authorize.Query().Get("state")

	resp, _ = h.get(t, "/oauth/callback?code=abc&state="+url.QueryEscape(state))
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != returnTo {
		t.Fatalf("callback: %d to %q", resp.StatusCode, resp.Header.Get("Location"))
	}
}

var csrfField = regexp.MustCompile(`name="csrf" value="([^"]+)"`)

func csrfFrom(t *testing.T, body string) string {
	t.Helper()
	m := csrfField.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("no csrf field in:\n%s", body)
	}
	return m[1]
}

// waitFor polls cond, holding the fake's lock, until it holds or times out.
func (h *harness) waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		h.gh.Mu.Lock()
		ok := cond()
		h.gh.Mu.Unlock()
		if ok {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func (h *harness) waitForStatus(t *testing.T, state string) fakegh.Status {
	t.Helper()
	var last fakegh.Status
	h.waitFor(t, "status "+state, func() bool {
		if n := len(h.gh.Statuses); n > 0 {
			last = h.gh.Statuses[n-1]
		}
		return last.State == state
	})
	return last
}

func TestSigningFlow(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	pr := check.Ref{Repo: "rotki", Number: 1}

	if err := h.checker.CheckPR(ctx, pr, check.Hint{}); err != nil {
		t.Fatal(err)
	}
	status := h.waitForStatus(t, "pending")
	if status.Description != "1 of 2 commit authors have signed the CLA." || !strings.Contains(status.TargetURL, "/sign?") {
		t.Fatalf("status %+v", status)
	}
	if len(h.gh.Comments) != 1 || !strings.Contains(h.gh.Comments[0].Body, "- [ ] @newbie") {
		t.Fatalf("comments %+v", h.gh.Comments)
	}

	signPath := "/sign?owner=rotki&pr=1&repo=rotki"
	_, body := h.get(t, signPath)
	// The agreement itself, then the login: not a link to it next to the
	// button.
	agreement, login := strings.Index(body, "chars of markdown"), strings.Index(body, "Log in with GitHub to sign")
	if agreement < 0 || login < agreement {
		t.Fatalf("logged-out sign page does not show the agreement before the login:\n%s", body)
	}

	h.login(t, signPath)
	// Revoked after the redirect, so the login does not wait for it.
	h.waitFor(t, "the user token revoked after login", func() bool { return h.gh.Revoked == 1 })
	_, body = h.get(t, signPath)
	if !strings.Contains(body, "chars of markdown") || !strings.Contains(body, "newbie@example.com") || strings.Contains(body, "unverified@example.com") {
		t.Fatalf("form:\n%s", body)
	}
	csrf := csrfFrom(t, body)

	form := url.Values{
		"csrf": {csrf}, "revision": {"rev1"}, "repo": {"rotki"}, "pr": {"1"},
		"name": {"New Contributor"}, "email": {"attacker@example.com"}, "category": {"individual"}, "agree": {"yes"},
	}
	resp, body := h.post(t, "/sign", form)
	if resp.StatusCode != http.StatusUnprocessableEntity || !strings.Contains(body, "verified email") {
		t.Fatalf("unverified email accepted: %d\n%s", resp.StatusCode, body)
	}

	form.Set("email", "work@example.com")
	form.Set("csrf", "forged")
	if resp, _ := h.post(t, "/sign", form); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("forged csrf: %d", resp.StatusCode)
	}

	form.Set("csrf", csrf)
	resp, body = h.post(t, "/sign", form)
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, "Your signature is saved") {
		t.Fatalf("sign: %d\n%s", resp.StatusCode, body)
	}

	raw := h.file("signatures/400.json")
	if raw == "" {
		t.Fatal("no record written")
	}
	if strings.Contains(raw, "work@example.com") || strings.Contains(raw, "New Contributor") {
		t.Fatalf("personal data stored in plain text:\n%s", raw)
	}
	var rec store.Record
	if err := json.Unmarshal([]byte(raw), &rec); err != nil {
		t.Fatal(err)
	}
	if rec.Login != "newbie" || rec.CLARevision != "rev1" || rec.PR != "rotki/rotki#1" || rec.KeyID != "test" {
		t.Fatalf("record %+v", rec)
	}
	personal, err := seal.Open(rec.PII, h.identity)
	if err != nil || personal.Email != "work@example.com" || personal.Name != "New Contributor" {
		t.Fatalf("sealed data %+v %v", personal, err)
	}

	status = h.waitForStatus(t, "success")
	if status.SHA != "head1" {
		t.Fatalf("status on %q", status.SHA)
	}
	// The status is set before the comment is edited, so wait for both.
	h.waitFor(t, "the comment to be edited in place", func() bool {
		return len(h.gh.Comments) == 1 && strings.Contains(h.gh.Comments[0].Body, "All commit authors have signed")
	})

	_, body = h.get(t, signPath)
	if !strings.Contains(body, "already signed") {
		t.Fatalf("second visit:\n%s", body)
	}
}

func TestEmployerSignatureNeedsAdmin(t *testing.T) {
	h := newHarness(t)
	h.login(t, "/sign")
	_, body := h.get(t, "/sign")
	form := url.Values{
		"csrf": {csrfFrom(t, body)}, "revision": {"rev1"},
		"name": {"New Contributor"}, "email": {"work@example.com"}, "category": {"employer"},
		"company": {""}, "role": {"CTO"}, "agree": {"yes"},
	}
	if resp, _ := h.post(t, "/sign", form); resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("employer without company accepted: %d", resp.StatusCode)
	}
	form.Set("company", "Example GmbH")
	_, body = h.post(t, "/sign", form)
	if !strings.Contains(body, "Waiting for confirmation") {
		t.Fatalf("done page:\n%s", body)
	}
	if !strings.Contains(h.file("pending/400.json"), `"company": "Example GmbH"`) {
		t.Fatalf("pending record %q", h.file("pending/400.json"))
	}

	// The signer is no admin.
	if resp, _ := h.get(t, "/admin"); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("non-admin got /admin: %d", resp.StatusCode)
	}

	h.gh.Admins["newbie"] = true
	h.login(t, "/admin")
	_, body = h.get(t, "/admin")
	if !strings.Contains(body, "Example GmbH") || !strings.Contains(body, "@newbie") {
		t.Fatalf("admin page:\n%s", body)
	}
	resp, _ := h.post(t, "/admin/confirm", url.Values{"csrf": {csrfFrom(t, body)}, "id": {"400"}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("confirm: %d", resp.StatusCode)
	}
	if h.file("pending/400.json") != "" || !strings.Contains(h.file("signatures/400.json"), `"confirmed_by": "newbie"`) {
		t.Fatalf("signed record after confirm: %s", h.file("signatures/400.json"))
	}
}

func TestOAuthCallbackRejectsWrongState(t *testing.T) {
	h := newHarness(t)
	h.get(t, "/login?return=/sign")
	resp, _ := h.get(t, "/oauth/callback?code=abc&state=wrong")
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("wrong state: %d", resp.StatusCode)
	}
}

func TestSafeReturn(t *testing.T) {
	cases := map[string]string{
		"/sign?pr=1":           "/sign?pr=1",
		"/admin":               "/admin",
		"https://evil.example": "/sign",
		"//evil.example":       "/sign",
		`/\evil.example`:       "/sign",
		"":                     "/sign",
	}
	for in, want := range cases {
		if got := safeReturn(in); got != want {
			t.Errorf("safeReturn(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCookiesArePurposeBound(t *testing.T) {
	c := cookies{key: []byte(strings.Repeat("k", 32)), now: time.Now}
	value, err := c.encode(oauthCookie, oauthState{State: "s"})
	if err != nil {
		t.Fatal(err)
	}
	var s session
	if err := c.decode(sessionCookie, value, &s); err == nil {
		t.Fatal("an oauth cookie decoded as a session")
	}
	var st oauthState
	if err := c.decode(oauthCookie, value, &st); err != nil || st.State != "s" {
		t.Fatalf("round trip: %+v %v", st, err)
	}
	if err := c.decode(oauthCookie, value+"x", &st); err == nil {
		t.Fatal("tampered cookie accepted")
	}
}

func TestLimiter(t *testing.T) {
	l := newLimiter(2, time.Minute)
	now := time.Now()
	for i, want := range []bool{true, true, false} {
		if got := l.allow(1, now); got != want {
			t.Fatalf("attempt %d: allow = %v, want %v", i+1, got, want)
		}
	}
	if !l.allow(2, now) {
		t.Fatal("limit shared between accounts")
	}
	if !l.allow(1, now.Add(2*time.Minute)) {
		t.Fatal("limit never resets")
	}
}

func TestPublicPagesMakeNoGitHubCalls(t *testing.T) {
	h := newHarness(t)
	h.gh.Mu.Lock()
	before := h.gh.Requests
	h.gh.Mu.Unlock()

	for _, path := range []string{"/", "/cla", "/sign?owner=rotki&repo=rotki&pr=1", "/healthz", "/ready"} {
		resp, _ := h.get(t, path)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s: %d", path, resp.StatusCode)
		}
	}

	h.gh.Mu.Lock()
	defer h.gh.Mu.Unlock()
	if h.gh.Requests != before {
		t.Fatalf("public pages made %d GitHub calls", h.gh.Requests-before)
	}
}

func TestUnchangedRecheckWritesNothing(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	pr := check.Ref{Repo: "rotki", Number: 1}
	if err := h.checker.CheckPR(ctx, pr, check.Hint{}); err != nil {
		t.Fatal(err)
	}

	writes := func() int {
		h.gh.Mu.Lock()
		defer h.gh.Mu.Unlock()
		n := 0
		for path, count := range h.gh.Paths {
			if !strings.HasPrefix(path, "GET ") && path != "POST /graphql" {
				n += count
			}
		}
		return n
	}
	first := writes()
	for range 3 {
		if err := h.checker.CheckPR(ctx, pr, check.Hint{}); err != nil {
			t.Fatal(err)
		}
	}
	if got := writes(); got != first {
		t.Fatalf("re-checks of an unchanged PR wrote %d times", got-first)
	}
	if !h.checker.UpToDate(pr, "head1") || h.checker.UpToDate(pr, "head2") {
		t.Fatal("UpToDate does not follow the head commit")
	}

	// A new commit is checked again.
	h.gh.Mu.Lock()
	p := h.gh.PRs["rotki#1"]
	p.HeadSHA = "head2"
	h.gh.PRs["rotki#1"] = p
	h.gh.Mu.Unlock()
	if err := h.checker.CheckPR(ctx, pr, check.Hint{}); err != nil {
		t.Fatal(err)
	}
	if status := h.waitForStatus(t, "pending"); status.SHA != "head2" {
		t.Fatalf("new head not reported: %+v", status)
	}
}

func TestForcedRecheckReportsAgain(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	pr := check.Ref{Repo: "rotki", Number: 1}
	if err := h.checker.CheckPR(ctx, pr, check.Hint{}); err != nil {
		t.Fatal(err)
	}
	h.gh.Mu.Lock()
	before := len(h.gh.Statuses)
	h.gh.Mu.Unlock()

	// The status vanished on GitHub; the sweep forces a re-check.
	if err := h.checker.CheckPR(ctx, pr, check.Hint{Force: true}); err != nil {
		t.Fatal(err)
	}
	h.gh.Mu.Lock()
	defer h.gh.Mu.Unlock()
	if len(h.gh.Statuses) != before+1 {
		t.Fatalf("forced re-check sent %d statuses", len(h.gh.Statuses)-before)
	}
}

func TestSessionEmailsAreCapped(t *testing.T) {
	var many []string
	for i := range 40 {
		many = append(many, strings.Repeat("x", 30)+string(rune('a'+i%26))+"@example.com")
	}
	many = append([]string{strings.Repeat("y", 300) + "@example.com"}, many...)
	got := sessionEmails(many)
	if len(got) != maxSessionEmails {
		t.Fatalf("kept %d emails", len(got))
	}
	for _, e := range got {
		if len(e) > 254 {
			t.Fatalf("kept an overlong address %q", e)
		}
	}

	c := cookies{key: []byte(strings.Repeat("k", 32)), now: time.Now}
	value, err := c.encode(sessionCookie, session{ID: 1, Login: "someone", Name: strings.Repeat("N", 200), Emails: got, CSRF: newToken()})
	if err != nil || len(value) > 3500 {
		t.Fatalf("session cookie is %d bytes", len(value))
	}
}

func TestMissingCLATextLoadsAtMostOncePerMinute(t *testing.T) {
	h := newHarness(t)
	st := store.New(h.data)
	if err := st.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Every load fails: the gist endpoint is not where the client looks.
	srv := &Server{Deps: Deps{Store: st, Agreement: store.NewAgreement(githubapp.NewPublicClient(h.gh.URL + "/broken"))}}
	now := time.Unix(1_800_000_000, 0)
	srv.now = func() time.Time { return now }

	h.gh.Mu.Lock()
	before := h.gh.Requests
	h.gh.Mu.Unlock()
	for range 5 {
		if _, ok := srv.claText(); ok {
			t.Fatal("no CLA expected")
		}
	}
	h.waitFor(t, "the one background load", func() bool { return h.gh.Requests > before })
	time.Sleep(50 * time.Millisecond)
	h.gh.Mu.Lock()
	calls := h.gh.Requests - before
	h.gh.Mu.Unlock()
	if calls != 1 {
		t.Fatalf("%d GitHub calls for 5 page views", calls)
	}
}

func TestLogoutEndsTheSession(t *testing.T) {
	h := newHarness(t)
	h.login(t, "/sign")
	_, body := h.get(t, "/sign")
	if resp, _ := h.post(t, "/logout", url.Values{"csrf": {"forged"}}); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("logout without the form token: %d", resp.StatusCode)
	}
	if resp, _ := h.post(t, "/logout", url.Values{"csrf": {csrfFrom(t, body)}}); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("logout: %d", resp.StatusCode)
	}
	if _, body := h.get(t, "/sign"); !strings.Contains(body, "Log in with GitHub") {
		t.Fatal("still logged in after logout")
	}
}

func TestSweepAfterRestartSendsNoDuplicateStatus(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	if err := h.checker.CheckPR(ctx, check.Ref{Repo: "rotki", Number: 1}, check.Hint{}); err != nil {
		t.Fatal(err)
	}
	h.gh.Mu.Lock()
	before := len(h.gh.Statuses)
	h.gh.Mu.Unlock()

	// A fresh checker remembers nothing, as after a restart.
	_, queue, sweeper := h.sweeper(t)
	sweeper.Sweep(ctx)
	if queue.Depth() != 1 {
		t.Fatalf("the sweep queued %d jobs", queue.Depth())
	}
	runCtx, cancel := context.WithCancel(ctx)
	go queue.Run(runCtx, 1)
	h.waitFor(t, "the queued check", func() bool { return queue.Depth() == 0 })
	time.Sleep(100 * time.Millisecond)
	cancel()

	h.gh.Mu.Lock()
	defer h.gh.Mu.Unlock()
	if len(h.gh.Statuses) != before {
		t.Fatalf("the restart re-sent %d unchanged statuses", len(h.gh.Statuses)-before)
	}
}

// sweeper returns a fresh checker, queue and sweeper on the harness's fake.
func (h *harness) sweeper(t *testing.T) (*check.Checker, *check.Queue, *reconcile.Sweeper) {
	t.Helper()
	checker := check.NewChecker(h.api, h.store, h.dir, check.Options{
		Owner: "rotki", StatusContext: "license/cla", BaseURL: h.site.URL,
		BotLogin: func() string { return h.app.Slug() + "[bot]" },
	})
	alerts := alert.New("")
	queue := check.NewQueue(checker, alerts, h.app.Limits, 10)
	// Loaded at startup in the service, so a sweep finds it cached.
	agreement := store.NewAgreement(githubapp.NewPublicClient(h.gh.URL))
	if err := agreement.Warm(context.Background(), h.store.Config()); err != nil {
		t.Fatal(err)
	}
	return checker, queue, reconcile.New(h.api, h.store, agreement, checker, queue, alerts, h.app.Limits, "rotki")
}

func TestSweepMakesNoRequestsWhenNothingChanged(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.gh.PRs["rotki#2"] = fakegh.PR{Open: true, HeadSHA: "head2", Commits: []fakegh.Commit{
		{AuthorName: "Other", AuthorID: 600, AuthorLogin: "other"},
	}}
	checker, _, sweeper := h.sweeper(t)
	for _, n := range []int{1, 2} {
		if err := checker.CheckPR(ctx, check.Ref{Repo: "rotki", Number: n}, check.Hint{}); err != nil {
			t.Fatal(err)
		}
	}

	h.gh.Mu.Lock()
	before := h.gh.Requests
	h.gh.Mu.Unlock()
	sweeper.Sweep(ctx)
	h.gh.Mu.Lock()
	calls := h.gh.Requests - before
	h.gh.Mu.Unlock()
	// The one search: the signatures are read from disk.
	if calls != 1 {
		t.Fatalf("an idle sweep made %d requests", calls)
	}
}

func TestUnrelatedSignatureLeavesOtherPullRequestsAlone(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.gh.PRs["rotki#2"] = fakegh.PR{Open: true, HeadSHA: "head2", Commits: []fakegh.Commit{
		{AuthorName: "Other", AuthorID: 600, AuthorLogin: "other"},
	}}
	checker, queue, sweeper := h.sweeper(t)
	for _, n := range []int{1, 2} {
		if err := checker.CheckPR(ctx, check.Ref{Repo: "rotki", Number: n}, check.Hint{}); err != nil {
			t.Fatal(err)
		}
	}

	// @other signs; @newbie on rotki#1 is unaffected.
	writeFile(t, h.data, "signatures/600.json", `{"github_id":600}`)
	sweeper.Sweep(ctx)
	if queue.Depth() != 1 {
		t.Fatalf("one signature queued %d pull requests", queue.Depth())
	}
	if !checker.UpToDate(check.Ref{Repo: "rotki", Number: 1}, "head1") {
		t.Fatal("the unrelated pull request was marked stale")
	}
	if checker.UpToDate(check.Ref{Repo: "rotki", Number: 2}, "head2") {
		t.Fatal("the signer's pull request was not marked stale")
	}

	// A config change touches everyone.
	writeFile(t, h.data, store.ConfigFile, `{"cla_gist":"gist1","cla_revision":"rev1","exempt_team":"core","allowlist":["x"]}`)
	if err := h.store.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if checker.UpToDate(check.Ref{Repo: "rotki", Number: 1}, "head1") {
		t.Fatal("a config change did not mark the pull request stale")
	}
}

func TestAdminRecheckIsLimitedToOncePerTenMinutes(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	if err := h.checker.CheckPR(ctx, check.Ref{Repo: "rotki", Number: 1}, check.Hint{}); err != nil {
		t.Fatal(err)
	}
	h.gh.Mu.Lock()
	statuses := len(h.gh.Statuses)
	h.gh.Mu.Unlock()

	now := time.Unix(1_800_000_000, 0)
	h.srv.now = func() time.Time { return now }

	// Not an admin.
	h.login(t, "/admin")
	if resp, _ := h.get(t, "/admin"); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("non-admin got the admin page: %d", resp.StatusCode)
	}

	h.gh.Admins["newbie"] = true
	h.login(t, "/admin")
	_, body := h.get(t, "/admin")
	if !strings.Contains(body, "No manual re-check since the service started") {
		t.Fatalf("admin page:\n%s", body)
	}
	csrf := csrfFrom(t, body)

	resp, _ := h.post(t, "/admin/recheck", url.Values{"csrf": {csrf}})
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/admin?recheck=started" {
		t.Fatalf("first re-check: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	h.waitFor(t, "the re-check to finish", func() bool {
		h.srv.recheckMu.Lock()
		defer h.srv.recheckMu.Unlock()
		return !h.srv.recheckRunning
	})

	resp, _ = h.post(t, "/admin/recheck", url.Values{"csrf": {csrf}})
	if resp.Header.Get("Location") != "/admin?recheck=limited" {
		t.Fatalf("second re-check within 10 minutes: %s", resp.Header.Get("Location"))
	}
	_, body = h.get(t, "/admin?recheck=limited")
	if !strings.Contains(body, "less than 10 minutes ago") || !strings.Contains(body, " disabled>") {
		t.Fatalf("limited page:\n%s", body)
	}

	now = now.Add(11 * time.Minute)
	resp, _ = h.post(t, "/admin/recheck", url.Values{"csrf": {csrf}})
	if resp.Header.Get("Location") != "/admin?recheck=started" {
		t.Fatalf("re-check after 10 minutes: %s", resp.Header.Get("Location"))
	}
	h.waitFor(t, "the second re-check to finish", func() bool {
		h.srv.recheckMu.Lock()
		defer h.srv.recheckMu.Unlock()
		return !h.srv.recheckRunning
	})
	time.Sleep(200 * time.Millisecond)

	// The pull request's result did not change, so no status was re-sent.
	h.gh.Mu.Lock()
	defer h.gh.Mu.Unlock()
	if len(h.gh.Statuses) != statuses {
		t.Fatalf("re-checks re-sent %d unchanged statuses", len(h.gh.Statuses)-statuses)
	}
}

func TestRecheckNeedsTheFormToken(t *testing.T) {
	h := newHarness(t)
	h.gh.Admins["newbie"] = true
	h.login(t, "/admin")
	if resp, _ := h.post(t, "/admin/recheck", url.Values{"csrf": {"forged"}}); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("forged re-check: %d", resp.StatusCode)
	}
}

func TestBrandingComesFromConfig(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	// Without a site block the org name stands in and the defaults apply.
	_, body := h.get(t, "/")
	if !strings.Contains(body, "Contributing to rotki") || !strings.Contains(body, `href="`+site.DefaultSource+`"`) {
		t.Fatalf("default branding:\n%s", body)
	}

	writeFile(t, h.data, store.ConfigFile, `{"cla_gist":"gist1","cla_revision":"rev1","exempt_team":"core",
	  "site":{"name":"Acme","legal_name":"Acme GmbH","homepage":"https://acme.example","source":"https://git.acme.example/cla","accent_color":"#ff8800"}}`)
	if err := h.store.Refresh(ctx); err != nil {
		t.Fatal(err)
	}

	_, body = h.get(t, "/")
	for _, want := range []string{"Contributing to Acme", "<title>Contributor License Agreement · Acme</title>", "© " + strconv.Itoa(time.Now().Year()) + " Acme GmbH",
		`href="https://acme.example"`, `href="https://git.acme.example/cla"`, `aria-hidden="true">a</span>`, `/theme.css?v=`} {
		if !strings.Contains(body, want) {
			t.Errorf("page lacks %q", want)
		}
	}
	if strings.Contains(strings.ToLower(body), "rotki") {
		t.Errorf("another organization's page still mentions rotki:\n%s", body)
	}

	resp, css := h.get(t, "/theme.css")
	if resp.Header.Get("Content-Type") != "text/css; charset=utf-8" || !strings.Contains(css, "rgb(255, 136, 0)") {
		t.Fatalf("theme: %s\n%s", resp.Header.Get("Content-Type"), css)
	}
}

// Admin rights are asked of GitHub, never kept in the session; the
// Directory caches the answer for a minute (see the org tests).
func TestANonAdminIsRefusedTheAdminPage(t *testing.T) {
	h := newHarness(t)
	h.login(t, "/admin")
	if resp, _ := h.get(t, "/admin"); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("a non-admin sees the page: %d", resp.StatusCode)
	}
}

func TestTheSessionCookieRevealsNothing(t *testing.T) {
	h := newHarness(t)
	h.login(t, "/sign")
	u, _ := url.Parse(h.site.URL)
	for _, ck := range h.client.Jar.Cookies(u) {
		if ck.Name != sessionCookie {
			continue
		}
		raw, _ := base64.RawURLEncoding.DecodeString(ck.Value)
		for _, secret := range []string{"newbie@example.com", "New Contributor", "newbie"} {
			if strings.Contains(string(raw), secret) || strings.Contains(ck.Value, secret) {
				t.Fatalf("the cookie reveals %q", secret)
			}
		}
		return
	}
	t.Fatal("no session cookie")
}

func TestSecureCookiesAreHostOnly(t *testing.T) {
	secure := cookies{secure: true}
	plain := cookies{}
	if secure.cookieName(sessionCookie) != "__Host-cla_session" || plain.cookieName(sessionCookie) != "cla_session" {
		t.Fatalf("names %q %q", secure.cookieName(sessionCookie), plain.cookieName(sessionCookie))
	}
	rec := httptest.NewRecorder()
	secure.set(rec, oauthCookie, "v", time.Minute)
	ck := rec.Result().Cookies()[0]
	if ck.Name != "__Host-cla_oauth" || !ck.Secure || ck.Path != "/" || ck.Domain != "" {
		t.Fatalf("cookie %+v", ck)
	}
}

func TestTheLogoReplacesTheLetterMark(t *testing.T) {
	h := newHarness(t)
	if resp, _ := h.get(t, "/logo"); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("a logo without a file: %d", resp.StatusCode)
	}
	if _, body := h.get(t, "/"); !strings.Contains(body, `class="brand-mark"`) {
		t.Fatal("no letter mark without a logo")
	}

	writeFile(t, h.data, store.LogoSVG, `<svg xmlns="http://www.w3.org/2000/svg"/>`)
	if err := h.store.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	_, body := h.get(t, "/")
	if !strings.Contains(body, `<img class="brand-logo" src="/logo?v=`) || strings.Contains(body, `class="brand-mark"`) {
		t.Fatalf("header without the logo:\n%s", body)
	}
	resp, logo := h.get(t, "/logo")
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != "image/svg+xml" || !strings.Contains(resp.Header.Get("Content-Security-Policy"), "sandbox") || !strings.Contains(logo, "<svg") {
		t.Fatalf("logo response %d %v", resp.StatusCode, resp.Header)
	}
}

func TestPagesOfferSigningOnlyToWhoStillNeedsTo(t *testing.T) {
	h := newHarness(t)
	for _, path := range []string{"/", "/cla"} {
		if _, body := h.get(t, path); !strings.Contains(body, `href="/sign"`) && !strings.Contains(body, "Log in with GitHub to sign") {
			t.Fatalf("logged out, %s offers no way to sign:\n%s", path, body)
		}
	}
	// @newbie (400) signs, then sees that instead of a sign button.
	writeFile(t, h.data, "signatures/400.json", `{"github_id":400}`)
	if err := h.store.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	h.login(t, "/")
	for _, path := range []string{"/", "/cla"} {
		_, body := h.get(t, path)
		if strings.Contains(body, "Read and sign the agreement") || strings.Contains(body, "Sign the agreement</a>") || !strings.Contains(body, "You have signed the agreement") {
			t.Fatalf("a signer is offered to sign on %s:\n%s", path, body)
		}
	}
}
