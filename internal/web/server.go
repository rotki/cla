// Package web serves the signing pages and the admin page: server-rendered
// html/template pages with one stylesheet, usable without JavaScript.
package web

import (
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"html/template"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rotki/cla/internal/alert"
	"github.com/rotki/cla/internal/check"
	"github.com/rotki/cla/internal/githubapp"
	"github.com/rotki/cla/internal/org"
	"github.com/rotki/cla/internal/seal"
	"github.com/rotki/cla/internal/site"
	"github.com/rotki/cla/internal/store"
	"github.com/rotki/cla/internal/version"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static
var staticFS embed.FS

var pages = []string{"index", "cla", "login", "form", "done", "standing", "admin", "error"}

// Deps is what the pages need from the rest of the service.
type Deps struct {
	App        *githubapp.App
	OAuth      *githubapp.OAuth
	Store      *store.Store
	Agreement  *store.Agreement
	Directory  *org.Directory
	Sealer     *seal.Sealer
	Checker    *check.Checker
	Queue      *check.Queue
	Alerts     *alert.Notifier
	Limits     *githubapp.Limits
	Rechecker  Rechecker
	Org        string
	SessionKey []byte
	Secure     bool
}

type Server struct {
	Deps
	cookies   cookies
	templates map[string]*template.Template
	limiter   *limiter
	now       func() time.Time
	warming   atomic.Bool

	recheckMu      sync.Mutex
	lastRecheck    time.Time
	recheckRunning bool
	// lastWarm is when a page last started loading the CLA text, in Unix
	// nanoseconds; it keeps failing loads to one attempt per minute.
	lastWarm atomic.Int64
}

func New(d Deps) (*Server, error) {
	s := &Server{
		Deps:      d,
		cookies:   cookies{key: d.SessionKey, secure: d.Secure, now: time.Now},
		templates: map[string]*template.Template{},
		limiter:   newLimiter(5, 10*time.Minute),
		now:       time.Now,
	}
	for _, page := range pages {
		t, err := template.ParseFS(templateFS, "templates/layout.html", "templates/"+page+".html")
		if err != nil {
			return nil, err
		}
		s.templates[page] = t
	}
	return s, nil
}

// Handler routes every page. webhook is mounted at /webhook.
func (s *Server) Handler(webhook http.Handler) http.Handler {
	mux := http.NewServeMux()
	static, _ := fs.Sub(staticFS, "static")
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(static)))
	mux.Handle("POST /webhook", webhook)
	mux.HandleFunc("GET /theme.css", s.theme)
	mux.HandleFunc("GET /logo", s.logo)
	mux.HandleFunc("GET /healthz", s.health)
	mux.HandleFunc("GET /ready", s.ready)
	mux.HandleFunc("GET /{$}", s.index)
	mux.HandleFunc("GET /cla", s.cla)
	mux.HandleFunc("GET /login", s.login)
	mux.HandleFunc("GET /oauth/callback", s.callback)
	mux.HandleFunc("POST /logout", s.logout)
	mux.HandleFunc("GET /sign", s.signPage)
	mux.HandleFunc("POST /sign", s.sign)
	mux.HandleFunc("GET /admin", s.adminPage)
	mux.HandleFunc("POST /admin/confirm", s.adminConfirm)
	mux.HandleFunc("POST /admin/reject", s.adminReject)
	mux.HandleFunc("POST /admin/recheck", s.adminRecheck)
	return accessLog(securityHeaders(mux, s.Secure))
}

// accessLog logs each request: method, path, status, duration and client.
// The query is left out, since the OAuth callback carries the code there.
// The client is X-Real-Ip, which the proxy in front sets, or the peer
// address; X-Forwarded-For is not used, as clients can prepend to it.
// Health probes from inside the container are not logged.
func accessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		remote := r.Header.Get("X-Real-Ip")
		if remote == "" {
			remote, _, _ = net.SplitHostPort(r.RemoteAddr)
		}
		if r.URL.Path == "/healthz" || r.URL.Path == "/ready" {
			if ip := net.ParseIP(remote); ip != nil && ip.IsLoopback() {
				return
			}
		}
		slog.Info("request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", rec.status,
			"duration", time.Since(start).String(),
			"remote", remote,
		)
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

// Unwrap lets http.ResponseController reach the underlying writer.
func (r *statusRecorder) Unwrap() http.ResponseWriter {
	return r.ResponseWriter
}

func securityHeaders(next http.Handler, https bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		if https {
			h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		h.Set("Content-Security-Policy", "default-src 'none'; style-src 'self'; img-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "same-origin")
		h.Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
}

// page is the data every template receives.
type page struct {
	Title   string
	Session *session
	Data    any
	Site    site.Site
	// Theme busts the browser cache of /theme.css when config.json changes.
	Theme string
	// Year is the current year, for the footer copyright.
	Year int
	// Logo is the version of the header logo, empty when there is none.
	Logo string
}

func (s *Server) render(w http.ResponseWriter, status int, name string, p page) {
	p.Site = s.site()
	p.Theme = s.Store.ConfigVersion()
	p.Year = s.now().Year()
	_, _, p.Logo = s.Store.Logo()
	var buf bytes.Buffer
	if err := s.templates[name].ExecuteTemplate(&buf, "layout", p); err != nil {
		slog.Error("rendering page failed", "page", name, "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = buf.WriteTo(w)
}

func (s *Server) fail(w http.ResponseWriter, r *http.Request, status int, message string) {
	s.render(w, status, "error", page{Title: "Something went wrong", Session: s.cookies.session(r), Data: message})
}

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status":  "ok",
		"version": version.Version,
		"git_sha": version.GitSHA,
	})
}

// ready reports whether the store is loaded, plus the numbers worth watching:
// the remaining GitHub quota and how much work is waiting. It leaves out the
// store's head, which would reveal when someone signs.
func (s *Server) ready(w http.ResponseWriter, _ *http.Request) {
	_, claLoaded := s.Agreement.Cached(s.Store.Config())
	status := http.StatusOK
	if !s.Store.Ready() {
		status = http.StatusServiceUnavailable
	}
	var quota map[string]githubapp.Quota
	if s.Limits != nil {
		quota = s.Limits.Snapshot()
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"store_ready": s.Store.Ready(),
		"cla_loaded":  claLoaded,
		"queue_depth": s.Queue.Depth(),
		"rate_limits": quota,
	})
}

// claText returns the cached agreement. When it is missing, a background load
// starts, at most one at a time and one a minute, and the page answers at
// once instead of waiting on GitHub. Normally the sweep has loaded it.
func (s *Server) claText() (store.CLAText, bool) {
	cfg := s.Store.Config()
	if text, ok := s.Agreement.Cached(cfg); ok {
		return text, true
	}
	now := s.now().UnixNano()
	if last := s.lastWarm.Load(); now-last < int64(time.Minute) || !s.lastWarm.CompareAndSwap(last, now) {
		return store.CLAText{}, false
	}
	if s.warming.CompareAndSwap(false, true) {
		go func() {
			defer s.warming.Store(false)
			ctx, cancel := detached()
			defer cancel()
			if err := s.Agreement.Warm(ctx, cfg); err != nil {
				slog.Error("loading the CLA text failed", "error", err)
			}
		}()
	}
	return store.CLAText{}, false
}

// site is the branding from config.json, with defaults.
func (s *Server) site() site.Site {
	return site.Resolve(s.Store.Config().Site, s.Org)
}

// theme serves the accent colour as CSS custom properties. The strict CSP
// allows no inline styles, so it is a stylesheet of its own.
func (s *Server) theme(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	_, _ = w.Write([]byte(s.site().ThemeCSS()))
}

// logo serves the optional header logo from the data directory. An SVG is a
// document that could carry scripts: it is shown only through an img tag,
// where none run, and served with a policy that forbids them should anyone
// open it directly.
func (s *Server) logo(w http.ResponseWriter, r *http.Request) {
	data, contentType, _ := s.Store.Logo()
	if data == nil {
		http.NotFound(w, r)
		return
	}
	h := w.Header()
	h.Set("Content-Type", contentType)
	// The page links it with its version, which changes with the file.
	h.Set("Cache-Control", "public, max-age=31536000, immutable")
	h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; sandbox")
	_, _ = w.Write(data)
}

func (s *Server) index(w http.ResponseWriter, r *http.Request) {
	sess := s.cookies.session(r)
	s.render(w, http.StatusOK, "index", page{Title: "Contributor License Agreement", Session: sess, Data: map[string]any{"Standing": s.standingOf(sess)}})
}

// standingOf is where a logged-in account stands, so pages offer signing
// only to someone who still needs to; nil when logged out or not loaded.
func (s *Server) standingOf(sess *session) *standingData {
	if sess == nil || !s.Store.Ready() {
		return nil
	}
	return &standingData{Standing: s.Store.StandingOf(sess.ID)}
}

func (s *Server) cla(w http.ResponseWriter, r *http.Request) {
	text, ok := s.claText()
	if !ok {
		s.fail(w, r, http.StatusServiceUnavailable, "The agreement text is being loaded. Please try again in a minute.")
		return
	}
	sess := s.cookies.session(r)
	s.render(w, http.StatusOK, "cla", page{Title: "Contributor License Agreement", Session: sess, Data: map[string]any{"CLA": text, "Standing": s.standingOf(sess)}})
}

// recheck queues the pull requests an account held up. Not the one in the
// signing link: anyone can put any pull request there, and these jobs may
// use the writes kept back for people.
func (s *Server) recheck(refs []check.Ref) {
	for _, ref := range refs {
		s.Queue.Enqueue(check.Job{Ref: ref, Signed: true})
	}
}

// limiter allows n attempts per window per account.
type limiter struct {
	n      int
	window time.Duration
	mu     sync.Mutex
	hits   map[int64][]time.Time
}

func newLimiter(n int, window time.Duration) *limiter {
	return &limiter{n: n, window: window, hits: map[int64][]time.Time{}}
}

func (l *limiter) allow(id int64, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	recent := l.hits[id][:0]
	for _, t := range l.hits[id] {
		if now.Sub(t) < l.window {
			recent = append(recent, t)
		}
	}
	if len(recent) >= l.n {
		l.hits[id] = recent
		return false
	}
	if len(l.hits) >= maxLimited {
		l.forget(now)
	}
	l.hits[id] = append(recent, now)
	return true
}

// maxLimited is how many accounts the limiter tracks before it drops the
// ones with no attempt left in the window.
const maxLimited = 1000

func (l *limiter) forget(now time.Time) {
	for id, hits := range l.hits {
		if len(hits) == 0 || now.Sub(hits[len(hits)-1]) >= l.window {
			delete(l.hits, id)
		}
	}
}

func detached() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 30*time.Second)
}
