// Package githubapp is a small GitHub client for the CLA App: App JWTs,
// cached installation tokens, REST and GraphQL calls, and the user login flow.
//
// Errors carry the method, path and status only. Response bodies are never
// put into an error, because errors end up in logs and alerts and a body can
// contain personal data.
package githubapp

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// APIError is a non-2xx answer from GitHub.
type APIError struct {
	Method string
	Path   string
	Status int
}

func (e *APIError) Error() string {
	return fmt.Sprintf("github %s %s: %d", e.Method, e.Path, e.Status)
}

// StatusOf returns the HTTP status of an APIError, or 0.
func StatusOf(err error) int {
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return apiErr.Status
	}
	return 0
}

// IsStatus reports whether err is an APIError with the given status.
func IsStatus(err error, status int) bool {
	return StatusOf(err) == status
}

// NoAccess reports whether GitHub refused or hid what was asked for: a 403
// that is not a rate limit, a 404, or a GraphQL FORBIDDEN or NOT_FOUND. For
// a repository that is what the App sees when it is not installed there or
// lacks a permission. Rate limits never reach here as NoAccess: they come
// back as a RateLimitError, which callers handle first.
func NoAccess(err error) bool {
	if _, limited := RetryAfter(err); limited || NotInstalled(err) {
		return false
	}
	switch StatusOf(err) {
	case http.StatusForbidden, http.StatusNotFound:
		return true
	}
	var gqlErr *GraphQLError
	if errors.As(err, &gqlErr) {
		for _, t := range gqlErr.Types {
			if t == "FORBIDDEN" || t == "NOT_FOUND" {
				return true
			}
		}
	}
	return false
}

// NotInstalled reports whether GitHub refused an installation token: the
// App was uninstalled from the organization or the installation suspended,
// so nothing at all can be checked, whichever repository asked.
func NotInstalled(err error) bool {
	var apiErr *APIError
	if !errors.As(err, &apiErr) || !strings.HasSuffix(apiErr.Path, "/access_tokens") {
		return false
	}
	return apiErr.Status == http.StatusNotFound || apiErr.Status == http.StatusForbidden
}

// CallGraphQL is what Call says for any GraphQL request; the error cannot
// tell which query it was, so callers that know replace it.
const CallGraphQL = "reading from GitHub's GraphQL API"

// Call names, in words, the GitHub request an error came from, for alerts.
// It is one of a fixed set of phrases, never request data, so it carries no
// personal data; "" when the request is not one of these.
func Call(err error) string {
	var gqlErr *GraphQLError
	if errors.As(err, &gqlErr) {
		return CallGraphQL
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		return ""
	}
	p := apiErr.Path
	switch {
	case strings.HasSuffix(p, "/access_tokens"):
		return "getting an installation token"
	case strings.HasPrefix(p, "/installation/repositories"):
		return "listing the installation's repositories"
	case strings.Contains(p, "/statuses/"):
		return "setting the commit status"
	case strings.Contains(p, "/comments"):
		return "reading or writing the bot comment"
	case strings.Contains(p, "/teams/"):
		return "reading the exempt team"
	case p == "/graphql":
		return CallGraphQL
	}
	return ""
}

type App struct {
	id     int64
	key    *rsa.PrivateKey
	apiURL string
	http   *http.Client
	now    func() time.Time
	// Limits tracks the installation's remaining quota.
	Limits *Limits
	pacer  *Pacer

	mu sync.Mutex

	// tokenMu guards tokens and minting; it is never held across a call.
	// Each scope has its own minting lock, so one slow mint holds up only
	// callers of that scope.
	tokenMu sync.Mutex
	tokens  map[string]cachedToken
	minting map[string]*sync.Mutex
	instID  int64
	slug    string
}

type cachedToken struct {
	token   string
	expires time.Time
}

// Scope narrows an installation token to some repositories and permissions.
// GitHub App permissions hold for every repo of the installation, so the
// service asks for the least it needs per use.
type Scope struct {
	Repositories []string          `json:"repositories,omitempty"`
	Permissions  map[string]string `json:"permissions,omitempty"`
}

func (s Scope) key() string {
	data, _ := json.Marshal(s)
	return string(data)
}

func New(id int64, key *rsa.PrivateKey, apiURL string) *App {
	return &App{
		id:      id,
		key:     key,
		apiURL:  apiURL,
		http:    &http.Client{Timeout: 30 * time.Second, Transport: transport()},
		now:     time.Now,
		tokens:  map[string]cachedToken{},
		minting: map[string]*sync.Mutex{},
		Limits:  NewLimits(),
		pacer:   NewPacer(time.Second),
	}
}

// transport keeps a few idle connections to GitHub open, so the workers and
// pages reuse TLS sessions instead of reconnecting in bursts.
func transport() *http.Transport {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.MaxIdleConnsPerHost = 8
	return t
}

// JWT returns a short-lived token that authenticates as the App itself.
func (a *App) JWT() (string, error) {
	now := a.now()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	claims, err := json.Marshal(map[string]any{
		// Backdated to absorb clock drift, as GitHub recommends.
		"iat": now.Add(-60 * time.Second).Unix(),
		"exp": now.Add(9 * time.Minute).Unix(),
		"iss": strconv.FormatInt(a.id, 10),
	})
	if err != nil {
		return "", err
	}
	signingInput := header + "." + base64.RawURLEncoding.EncodeToString(claims)
	digest := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, a.key, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// Init resolves the App's slug and its installation on org. The service
// works for one org, so one installation token serves every call.
func (a *App) Init(ctx context.Context, org string) error {
	var app struct {
		Slug string `json:"slug"`
	}
	if err := a.appCall(ctx, http.MethodGet, "/app", nil, &app); err != nil {
		return err
	}
	var inst struct {
		ID int64 `json:"id"`
	}
	if err := a.appCall(ctx, http.MethodGet, "/orgs/"+org+"/installation", nil, &inst); err != nil {
		return err
	}
	a.mu.Lock()
	a.slug = app.Slug
	a.instID = inst.ID
	a.mu.Unlock()
	return nil
}

// SetWriteGap changes the spacing between writes; tests set it to zero.
func (a *App) SetWriteGap(d time.Duration) {
	a.pacer.mu.Lock()
	a.pacer.gap = d
	a.pacer.mu.Unlock()
}

// Slug is the App's URL name; its comments are authored by "<slug>[bot]".
func (a *App) Slug() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.slug
}

// InstallationID is the installation on the configured org.
func (a *App) InstallationID() int64 {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.instID
}

// Token returns an installation token for scope, refreshed a few minutes
// before expiry.
func (a *App) Token(ctx context.Context, scope Scope) (string, error) {
	key := scope.key()
	if t, ok := a.cachedToken(key); ok {
		return t, nil
	}

	a.tokenMu.Lock()
	lock := a.minting[key]
	if lock == nil {
		lock = &sync.Mutex{}
		a.minting[key] = lock
	}
	a.tokenMu.Unlock()

	lock.Lock()
	defer lock.Unlock()
	if t, ok := a.cachedToken(key); ok {
		return t, nil // minted by whoever held the lock before us
	}
	var out struct {
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	path := fmt.Sprintf("/app/installations/%d/access_tokens", a.InstallationID())
	if err := a.appCall(ctx, http.MethodPost, path, scope, &out); err != nil {
		return "", err
	}
	a.tokenMu.Lock()
	a.tokens[key] = cachedToken{token: out.Token, expires: out.ExpiresAt}
	a.tokenMu.Unlock()
	return out.Token, nil
}

func (a *App) cachedToken(key string) (string, bool) {
	a.tokenMu.Lock()
	defer a.tokenMu.Unlock()
	t, ok := a.tokens[key]
	return t.token, ok && a.now().Before(t.expires.Add(-5*time.Minute))
}

func (a *App) appCall(ctx context.Context, method, path string, body, out any) error {
	jwt, err := a.JWT()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	_, err = do(ctx, a.http, nil, a.apiURL, "Bearer "+jwt, request{method: method, path: path, body: body, out: out})
	return err
}

// Client returns a REST/GraphQL client authenticated as the installation,
// with its token narrowed to scope. All installation clients share one quota
// tracker and one write pacer, since they share one installation quota.
func (a *App) Client(scope Scope) *Client {
	return &Client{
		apiURL:  a.apiURL,
		http:    a.http,
		timeout: callTimeout,
		limits:  a.Limits,
		pacer:   a.pacer,
		auth: func(ctx context.Context) (string, error) {
			t, err := a.Token(ctx, scope)
			return "token " + t, err
		},
	}
}

// UserClient returns a client authenticated with a user's access token.
func (a *App) UserClient(token string) *Client {
	return &Client{
		apiURL:  a.apiURL,
		http:    a.http,
		timeout: callTimeout,
		auth: func(context.Context) (string, error) {
			return "Bearer " + token, nil
		},
	}
}

// callTimeout bounds every GitHub call made by the service. A slow GitHub
// must never hold a page or a worker for minutes.
const callTimeout = 10 * time.Second

type Client struct {
	apiURL  string
	http    *http.Client
	auth    func(ctx context.Context) (string, error)
	timeout time.Duration
	limits  *Limits
	pacer   *Pacer
}

type interactiveKey struct{}

// WithInteractive marks writes made with ctx as done for someone waiting:
// they may use the part of the write budget the background sweep cannot.
func WithInteractive(ctx context.Context) context.Context {
	return context.WithValue(ctx, interactiveKey{}, true)
}

func interactive(ctx context.Context) bool {
	v, _ := ctx.Value(interactiveKey{}).(bool)
	return v
}

// NewClient builds a client with a fixed token, for the command line tools.
func NewClient(apiURL, token string) *Client {
	return &Client{
		apiURL:  strings.TrimRight(apiURL, "/"),
		http:    &http.Client{Timeout: 60 * time.Second},
		timeout: 60 * time.Second,
		auth: func(context.Context) (string, error) {
			return "Bearer " + token, nil
		},
	}
}

// NewPublicClient builds an unauthenticated client. Installation tokens cannot
// read gists, and the CLA gist is public.
func NewPublicClient(apiURL string) *Client {
	return &Client{
		apiURL:  strings.TrimRight(apiURL, "/"),
		http:    &http.Client{Timeout: 30 * time.Second},
		timeout: callTimeout,
		auth:    func(context.Context) (string, error) { return "", nil },
		// Its own tracking: unauthenticated calls have their own small
		// quota (60 an hour per address), and must stop while it is spent.
		limits: NewLimits(),
	}
}

type request struct {
	method, path string
	body, out    any
}

type response struct {
	header http.Header
}

// Do calls the REST API. body is JSON encoded when not nil; out is decoded
// when not nil. It returns the response headers for pagination.
func (c *Client) Do(ctx context.Context, method, path string, body, out any) (http.Header, error) {
	resp, err := c.send(ctx, request{method: method, path: path, body: body, out: out})
	return resp.header, err
}

func (c *Client) send(ctx context.Context, r request) (response, error) {
	// While GitHub has us limited, nothing goes out: fail fast and let the
	// caller reschedule.
	if c.limits != nil {
		resource := "core"
		if r.path == "/graphql" {
			resource = "graphql"
		}
		if until, blocked := c.limits.Blocked(resource); blocked {
			return response{}, &RateLimitError{APIError: APIError{Method: r.method, Path: trimQuery(r.path)}, RetryAt: until}
		}
	}
	// Waiting for a write slot is not part of the call: the timeout starts
	// once the request may go out.
	var slot time.Time
	paced := c.pacer != nil && mutates(r.method, r.path)
	if paced {
		var err error
		if slot, err = c.pacer.Wait(ctx, interactive(ctx)); err != nil {
			return response{}, err
		}
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	auth, err := c.auth(ctx)
	if err != nil {
		if paced {
			c.pacer.Release(slot)
		}
		return response{}, err
	}
	return do(ctx, c.http, c.limits, c.apiURL, auth, r)
}

// mutates reports whether a call writes. GraphQL queries and markdown
// rendering are POSTs that only read.
func mutates(method, path string) bool {
	if method == http.MethodGet || method == http.MethodHead {
		return false
	}
	return path != "/graphql" && path != "/markdown"
}

// DoRaw calls the REST API and returns the body unparsed, for endpoints that
// answer with HTML or text.
func (c *Client) DoRaw(ctx context.Context, method, path string, body any) ([]byte, error) {
	var raw rawBody
	if _, err := c.Do(ctx, method, path, body, &raw); err != nil {
		return nil, err
	}
	return raw, nil
}

// rawBody marks a response that must not be JSON decoded.
type rawBody []byte

// Paginate follows Link headers and calls each for every page, decoded into
// a fresh T.
func Paginate[T any](ctx context.Context, c *Client, path string, each func(T) error) error {
	next := path
	for next != "" {
		var page T
		header, err := c.Do(ctx, http.MethodGet, next, nil, &page)
		if err != nil {
			return err
		}
		if err := each(page); err != nil {
			return err
		}
		next = nextLink(header.Get("Link"), c.apiURL)
	}
	return nil
}

func nextLink(link, apiURL string) string {
	for part := range strings.SplitSeq(link, ",") {
		segments := strings.Split(strings.TrimSpace(part), ";")
		if len(segments) < 2 || strings.TrimSpace(segments[1]) != `rel="next"` {
			continue
		}
		u := strings.Trim(strings.TrimSpace(segments[0]), "<>")
		return strings.TrimPrefix(u, apiURL)
	}
	return ""
}

// GraphQLError is returned when the GraphQL response carries errors. Like
// APIError it keeps no message text, only GitHub's error types (NOT_FOUND,
// FORBIDDEN and the like), a fixed vocabulary.
type GraphQLError struct {
	Count int
	Types []string
}

func (e *GraphQLError) Error() string {
	return fmt.Sprintf("github graphql: %d errors", e.Count)
}

// GraphQL runs a query and decodes its data into out.
func (c *Client) GraphQL(ctx context.Context, query string, vars map[string]any, out any) error {
	var resp struct {
		Data   json.RawMessage `json:"data"`
		Errors []struct {
			Type    string `json:"type"`
			Message string `json:"message"`
		} `json:"errors"`
	}
	header, err := c.Do(ctx, http.MethodPost, "/graphql", map[string]any{"query": query, "variables": vars}, &resp)
	if err != nil {
		return err
	}
	if len(resp.Errors) == 0 {
		return json.Unmarshal(resp.Data, out)
	}

	// GraphQL reports rate limits with a 200: a RATE_LIMITED error type, a
	// message naming the limit, or no quota left in the headers. Messages
	// are only inspected, never kept.
	limited := header.Get("X-RateLimit-Remaining") == "0"
	for _, e := range resp.Errors {
		if e.Type == "RATE_LIMITED" || strings.Contains(strings.ToLower(e.Message), "rate limit") {
			limited = true
		}
	}
	if !limited {
		gqlErr := &GraphQLError{Count: len(resp.Errors)}
		for _, e := range resp.Errors {
			gqlErr.Types = append(gqlErr.Types, e.Type)
		}
		return gqlErr
	}
	retryAt, ok := retryTime(header, time.Now())
	if !ok {
		retryAt = time.Now().Add(time.Minute)
	}
	if c.limits != nil && secondary(header) {
		c.limits.Block(retryAt)
	}
	return &RateLimitError{APIError: APIError{Method: http.MethodPost, Path: "/graphql"}, RetryAt: retryAt}
}

func do(ctx context.Context, client *http.Client, limits *Limits, apiURL, auth string, r request) (response, error) {
	var reader io.Reader
	if r.body != nil {
		data, err := json.Marshal(r.body)
		if err != nil {
			return response{}, err
		}
		reader = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, r.method, apiURL+r.path, reader)
	if err != nil {
		return response{}, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	if r.body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	path := trimQuery(r.path)
	resp, err := client.Do(req)
	if err != nil {
		return response{}, fmt.Errorf("github %s %s: %w", r.method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if limits != nil {
		limits.observe(resp.Header)
	}
	out := response{header: resp.Header}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// The body is only inspected for the secondary rate limit marker,
		// never kept.
		head, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		_, _ = io.Copy(io.Discard, resp.Body)
		apiErr := APIError{Method: r.method, Path: path, Status: resp.StatusCode}
		if retryAt, limited := rateLimited(resp, head, time.Now()); limited {
			if limits != nil && secondary(resp.Header) {
				limits.Block(retryAt)
			}
			return out, &RateLimitError{APIError: apiErr, RetryAt: retryAt}
		}
		return out, &apiErr
	}
	if r.out == nil || resp.StatusCode == http.StatusNoContent {
		_, _ = io.Copy(io.Discard, resp.Body)
		return out, nil
	}
	if raw, ok := r.out.(*rawBody); ok {
		data, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
		*raw = data
		return out, err
	}
	if err := json.NewDecoder(resp.Body).Decode(r.out); err != nil {
		return out, fmt.Errorf("github %s %s: decoding response: %w", r.method, path, err)
	}
	return out, nil
}

func trimQuery(path string) string {
	if i := strings.IndexByte(path, '?'); i >= 0 {
		return path[:i]
	}
	return path
}
