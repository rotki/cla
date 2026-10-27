package web

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/rotki/cla/internal/alert"
	"github.com/rotki/cla/internal/check"
	"github.com/rotki/cla/internal/githubapp"
	"github.com/rotki/cla/internal/seal"
	"github.com/rotki/cla/internal/store"
)

var repoName = regexp.MustCompile(`^[A-Za-z0-9._-]{1,100}$`)

// prContext is the pull request a signer came from. It only shapes links and
// which pull request is recorded as the origin; it grants nothing.
type prContext struct {
	Repo   string
	Number int
	URL    string
}

func (p *prContext) String() string {
	return fmt.Sprintf("%s#%d", p.Repo, p.Number)
}

func (s *Server) parsePR(owner, repo, number string) *prContext {
	n, err := strconv.Atoi(number)
	if !strings.EqualFold(owner, s.Org) || !repoName.MatchString(repo) || err != nil || n <= 0 {
		return nil
	}
	return &prContext{Repo: repo, Number: n, URL: fmt.Sprintf("https://github.com/%s/%s/pull/%d", s.Org, repo, n)}
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	verifier, state := githubapp.NewVerifier()
	value, err := s.cookies.encode(oauthCookie, oauthState{
		State:    state,
		Verifier: verifier,
		Return:   safeReturn(r.URL.Query().Get("return")),
		Exp:      s.now().Add(oauthTTL).Unix(),
	})
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, "Could not start the login. Please try again.")
		return
	}
	s.cookies.set(w, oauthCookie, value, oauthTTL)
	http.Redirect(w, r, s.OAuth.AuthorizeURL(state, verifier), http.StatusFound)
}

func (s *Server) callback(w http.ResponseWriter, r *http.Request) {
	ck, err := s.cookies.get(r, oauthCookie)
	var st oauthState
	if err != nil || s.cookies.decode(oauthCookie, ck.Value, &st) != nil || s.now().Unix() > st.Exp {
		s.fail(w, r, http.StatusBadRequest, "Your login took too long or was started elsewhere. Please start again from the signing link.")
		return
	}
	s.cookies.clear(w, oauthCookie)

	q := r.URL.Query()
	if subtle.ConstantTimeCompare([]byte(q.Get("state")), []byte(st.State)) != 1 || q.Get("code") == "" {
		s.fail(w, r, http.StatusBadRequest, "The login could not be verified. Please start again from the signing link.")
		return
	}

	token, err := s.OAuth.Exchange(r.Context(), q.Get("code"), st.Verifier)
	if err != nil {
		slog.Warn("oauth exchange failed", "error", err)
		s.fail(w, r, http.StatusBadGateway, "GitHub did not accept the login. Please try again.")
		return
	}
	// The token is used for these two calls only, then revoked: a GitHub App
	// user token would otherwise stay valid for hours. The revoke does not
	// hold up the redirect.
	user, emails, err := githubapp.FetchUser(r.Context(), s.App.UserClient(token))
	go func() {
		ctx, cancel := detached()
		defer cancel()
		if revokeErr := s.OAuth.Revoke(ctx, token); revokeErr != nil {
			slog.Warn("revoking the user token failed", "error", revokeErr)
		}
	}()
	if err != nil {
		slog.Warn("fetching the user after login failed", "error", err)
		s.fail(w, r, http.StatusBadGateway, "Could not read your GitHub account. Please try again.")
		return
	}

	// Admin rights are not looked up here: most logins are contributors
	// signing. A cached answer is dropped, so logging in again is how a new
	// admin gets the page without waiting.
	s.Directory.Forget(user.Login)
	err = s.cookies.setSession(w, session{
		ID:     user.ID,
		Login:  user.Login,
		Name:   user.Name,
		Emails: sessionEmails(emails),
		CSRF:   newToken(),
	})
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, "Could not complete the login. Please try again.")
		return
	}
	http.Redirect(w, r, st.Return, http.StatusFound)
}

// maxSessionEmails keeps the session cookie well under the browser's ~4 KB
// limit. The primary address comes first, so it is always kept.
const maxSessionEmails = 10

func sessionEmails(verified []string) []string {
	out := make([]string, 0, min(len(verified), maxSessionEmails))
	for _, e := range verified {
		if len(out) == maxSessionEmails {
			break
		}
		if len(e) <= 254 {
			out = append(out, e)
		}
	}
	return out
}

type formData struct {
	CLA      store.CLAText
	PR       *prContext
	Name     string
	Email    string
	Category string
	Company  string
	Role     string
	Errors   []string
}

type standingData struct {
	Standing store.Standing
	PR       *prContext
}

func (d standingData) Grandfathered() bool { return d.Standing == store.GrandfatheredIn }
func (d standingData) Pending() bool       { return d.Standing == store.Pending }
func (d standingData) Signed() bool        { return d.Standing == store.Signed }

// Covered reports whether there is nothing to sign: signed, grandfathered
// or waiting for an admin.
func (d standingData) Covered() bool { return d.Standing != store.NotSigned }

func (s *Server) signPage(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	pr := s.parsePR(q.Get("owner"), q.Get("repo"), q.Get("pr"))
	sess := s.cookies.session(r)
	if sess == nil {
		// The agreement comes first, the login after it: nobody is sent to
		// sign something they were only offered a link to.
		text, ok := s.claText()
		if !ok {
			s.fail(w, r, http.StatusServiceUnavailable, "The agreement text is being loaded. Please try again in a minute.")
			return
		}
		loginURL := "/login?return=" + url.QueryEscape(r.URL.RequestURI())
		s.render(w, http.StatusOK, "login", page{Title: "Sign the CLA", Data: map[string]any{"LoginURL": loginURL, "PR": pr, "CLA": text}})
		return
	}
	if !s.Store.Ready() {
		s.fail(w, r, http.StatusServiceUnavailable, "The service is starting up. Please try again in a minute.")
		return
	}
	if standing := s.Store.StandingOf(sess.ID); standing != store.NotSigned {
		s.render(w, http.StatusOK, "standing", page{Title: "Sign the CLA", Session: sess, Data: standingData{standing, pr}})
		return
	}
	s.showForm(w, r, sess, http.StatusOK, formData{PR: pr, Name: sess.Name, Category: store.Individual})
}

func (s *Server) showForm(w http.ResponseWriter, r *http.Request, sess *session, status int, d formData) {
	text, ok := s.claText()
	if !ok {
		s.fail(w, r, http.StatusServiceUnavailable, "The agreement text is being loaded. Please try again in a minute.")
		return
	}
	d.CLA = text
	s.render(w, status, "form", page{Title: "Sign the CLA", Session: sess, Data: d})
}

func (s *Server) sign(w http.ResponseWriter, r *http.Request) {
	sess := s.cookies.session(r)
	if sess == nil {
		s.fail(w, r, http.StatusUnauthorized, "Your session expired. Please open the signing link again.")
		return
	}
	if err := r.ParseForm(); err != nil || !validCSRF(sess, r.PostForm.Get("csrf")) {
		s.fail(w, r, http.StatusForbidden, "The form could not be verified. Please open the signing link again.")
		return
	}
	if !s.Store.Ready() || s.Store.Config().CLARevision == "" {
		s.fail(w, r, http.StatusServiceUnavailable, "The service is starting up. Please try again in a minute.")
		return
	}
	if !s.limiter.allow(sess.ID, s.now()) {
		s.fail(w, r, http.StatusTooManyRequests, "Too many attempts. Please wait a few minutes.")
		return
	}

	f := r.PostForm
	d := formData{
		PR:       s.parsePR(s.Org, f.Get("repo"), f.Get("pr")),
		Name:     strings.TrimSpace(f.Get("name")),
		Email:    f.Get("email"),
		Category: f.Get("category"),
		Company:  strings.TrimSpace(f.Get("company")),
		Role:     strings.TrimSpace(f.Get("role")),
	}
	cfg := s.Store.Config()
	if f.Get("revision") != cfg.CLARevision {
		d.Errors = append(d.Errors, "The agreement was updated while you were reading it. Please review it again before signing.")
	}
	d.Errors = append(d.Errors, validate(d, sess.Emails, f.Get("agree") == "yes")...)
	if len(d.Errors) > 0 {
		s.showForm(w, r, sess, http.StatusUnprocessableEntity, d)
		return
	}

	sealed, err := s.Sealer.Seal(seal.Personal{Name: d.Name, Email: d.Email})
	if err != nil {
		slog.Error("sealing a signature failed", "error", err)
		s.fail(w, r, http.StatusInternalServerError, "Your signature could not be saved. Nothing was stored; please try again.")
		return
	}
	rec := store.Record{
		GitHubID:    sess.ID,
		Login:       sess.Login,
		SignedAt:    s.now().UTC(),
		CLARevision: cfg.CLARevision,
		Category:    d.Category,
		Origin:      "online",
		KeyID:       s.Sealer.KeyID(),
		PII:         sealed,
	}
	if d.Category == store.Employer {
		rec.Company = d.Company
		rec.Role = d.Role
	}
	// The pull request comes from the form, so it is recorded only when the
	// checker saw this account holding it up.
	blocked := s.Checker.BlockedBy(sess.ID)
	if d.PR != nil && slices.Contains(blocked, check.Ref{Repo: d.PR.Repo, Number: d.PR.Number}) {
		rec.PR = s.Org + "/" + d.PR.String()
	}

	// A client hanging up must not abort a commit halfway.
	ctx, cancel := detached()
	defer cancel()
	err = s.Store.Create(ctx, rec)
	switch {
	case errors.Is(err, store.ErrExists):
		// The store refreshed before refusing, so the standing shown is current.
		s.render(w, http.StatusOK, "standing", page{Title: "Sign the CLA", Session: sess, Data: standingData{s.Store.StandingOf(sess.ID), d.PR}})
		return
	case err != nil:
		slog.Error("storing a signature failed", "error", err)
		s.Alerts.Report(alert.StoreWrite, alert.Detail{Status: githubapp.StatusOf(err)})
		s.fail(w, r, http.StatusServiceUnavailable, "Your signature could not be saved right now. Please try again in a few minutes.")
		return
	}
	s.Alerts.Resolve(alert.StoreWrite)
	s.recheck(blocked)
	s.render(w, http.StatusOK, "done", page{Title: "Thank you", Session: sess, Data: map[string]any{"Pending": d.Category == store.Employer, "PR": d.PR}})
}

func validCSRF(sess *session, token string) bool {
	return token != "" && subtle.ConstantTimeCompare([]byte(token), []byte(sess.CSRF)) == 1
}

func validate(d formData, verified []string, agreed bool) []string {
	var errs []string
	if d.Name == "" || utf8.RuneCountInString(d.Name) > 200 {
		errs = append(errs, "Please enter your full name (up to 200 characters).")
	}
	if !slices.Contains(verified, d.Email) {
		errs = append(errs, "Please pick one of the verified email addresses of your GitHub account.")
	}
	switch d.Category {
	case store.Individual:
	case store.Employer:
		if d.Company == "" || utf8.RuneCountInString(d.Company) > 200 {
			errs = append(errs, "Please enter your employer's name (up to 200 characters).")
		}
		if d.Role == "" || utf8.RuneCountInString(d.Role) > 100 {
			errs = append(errs, "Please enter your role at your employer (up to 100 characters).")
		}
	default:
		errs = append(errs, "Please choose whether you sign for yourself or for your employer.")
	}
	if !agreed {
		errs = append(errs, "Please confirm that you have read and agree to the CLA.")
	}
	return errs
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if sess := s.cookies.session(r); sess != nil {
		if err := r.ParseForm(); err != nil || !validCSRF(sess, r.PostForm.Get("csrf")) {
			s.fail(w, r, http.StatusForbidden, "The form could not be verified. Please reload the page.")
			return
		}
	}
	s.cookies.clear(w, sessionCookie)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
