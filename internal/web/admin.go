package web

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"time"

	"github.com/rotki/cla/internal/alert"
	"github.com/rotki/cla/internal/githubapp"
	"github.com/rotki/cla/internal/store"
)

// requireAdmin returns the session of an org admin, or answers the request.
func (s *Server) requireAdmin(w http.ResponseWriter, r *http.Request) *session {
	sess := s.cookies.session(r)
	if sess == nil {
		if r.Method == http.MethodGet {
			http.Redirect(w, r, "/login?return="+url.QueryEscape("/admin"), http.StatusFound)
		} else {
			s.fail(w, r, http.StatusUnauthorized, "Your session expired. Please log in again.")
		}
		return nil
	}
	// Asked of GitHub, not remembered in the session: the page shows
	// companies and roles, and a removed admin must lose them within a
	// minute (see org.Directory.IsAdmin).
	if admin, err := s.Directory.IsAdmin(r.Context(), sess.Login); err != nil || !admin {
		s.fail(w, r, http.StatusForbidden, "Only admins of the GitHub organization can open this page.")
		return nil
	}
	return sess
}

func (s *Server) adminPage(w http.ResponseWriter, r *http.Request) {
	sess := s.requireAdmin(w, r)
	if sess == nil {
		return
	}
	records, err := s.Store.PendingRecords(r.Context())
	if err != nil {
		slog.Error("listing pending signatures failed", "error", err)
		s.Alerts.Report(alert.StoreRead, alert.Detail{Status: githubapp.StatusOf(err)})
		s.fail(w, r, http.StatusServiceUnavailable, "Pending signatures could not be loaded. Please try again.")
		return
	}
	sort.Slice(records, func(i, j int) bool { return records[i].SignedAt.Before(records[j].SignedAt) })

	s.recheckMu.Lock()
	last, running := s.lastRecheck, s.recheckRunning
	s.recheckMu.Unlock()
	data := adminData{
		Records:     records,
		LastRecheck: last,
		Running:     running,
		QueueDepth:  s.Queue.Depth(),
		Notice:      recheckNotices[r.URL.Query().Get("recheck")],
	}
	if !last.IsZero() {
		data.NextRecheck = last.Add(recheckInterval)
		data.CanRecheck = !running && !s.now().Before(data.NextRecheck)
	} else {
		data.CanRecheck = !running
	}
	s.render(w, http.StatusOK, "admin", page{Title: "Admin", Session: sess, Data: data})
}

// recheckInterval is the least time between two manual re-checks, for the
// whole service: each one walks every open pull request.
const recheckInterval = 10 * time.Minute

// Rechecker runs a manual re-check of every open pull request.
type Rechecker interface {
	RecheckAll(ctx context.Context) (int, error)
}

type adminData struct {
	Records     []store.PendingRecord
	LastRecheck time.Time
	NextRecheck time.Time
	Running     bool
	CanRecheck  bool
	QueueDepth  int
	Notice      string
}

// recheckNotices are the only messages the ?recheck= parameter can show.
var recheckNotices = map[string]string{
	"started": "Re-check started. Pull requests are re-checked in the background over the next minutes.",
	"limited": "A re-check ran less than 10 minutes ago or is still running. Please wait before starting another.",
}

func (s *Server) adminRecheck(w http.ResponseWriter, r *http.Request) {
	sess := s.adminPost(w, r)
	if sess == nil {
		return
	}

	s.recheckMu.Lock()
	if s.recheckRunning || (!s.lastRecheck.IsZero() && s.now().Before(s.lastRecheck.Add(recheckInterval))) {
		s.recheckMu.Unlock()
		http.Redirect(w, r, "/admin?recheck=limited", http.StatusSeeOther)
		return
	}
	s.lastRecheck, s.recheckRunning = s.now(), true
	s.recheckMu.Unlock()

	slog.Info("manual re-check started", "admin_id", sess.ID)
	go func() {
		defer func() {
			s.recheckMu.Lock()
			s.recheckRunning = false
			s.recheckMu.Unlock()
		}()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		queued, err := s.Rechecker.RecheckAll(ctx)
		if err != nil {
			slog.Error("manual re-check failed", "error", err)
			s.Alerts.Report(alert.ReconcileError, alert.Detail{Status: githubapp.StatusOf(err)})
			return
		}
		slog.Info("manual re-check queued", "pull_requests", queued)
	}()
	http.Redirect(w, r, "/admin?recheck=started", http.StatusSeeOther)
}

func (s *Server) adminConfirm(w http.ResponseWriter, r *http.Request) {
	s.adminAction(w, r, func(id int64, digest, admin string) error {
		ctx, cancel := detached()
		defer cancel()
		return s.Store.Confirm(ctx, id, digest, admin, s.now())
	})
}

func (s *Server) adminReject(w http.ResponseWriter, r *http.Request) {
	s.adminAction(w, r, func(id int64, digest, admin string) error {
		ctx, cancel := detached()
		defer cancel()
		return s.Store.Reject(ctx, id, digest, admin)
	})
}

// adminPost authorises an admin form post: an admin session, as
// requireAdmin checks it, and its form token.
func (s *Server) adminPost(w http.ResponseWriter, r *http.Request) *session {
	sess := s.requireAdmin(w, r)
	if sess == nil {
		return nil
	}
	if err := r.ParseForm(); err != nil || !validCSRF(sess, r.PostForm.Get("csrf")) {
		s.fail(w, r, http.StatusForbidden, "The form could not be verified. Please reload the page.")
		return nil
	}
	return sess
}

// adminAction applies a decision on one pending signature. The form names
// the record by its digest as well as the account, so a page loaded before
// the record was replaced cannot decide on the replacement.
func (s *Server) adminAction(w http.ResponseWriter, r *http.Request, act func(id int64, digest, admin string) error) {
	sess := s.adminPost(w, r)
	if sess == nil {
		return
	}
	id, err := strconv.ParseInt(r.PostForm.Get("id"), 10, 64)
	if err != nil || id <= 0 {
		s.fail(w, r, http.StatusBadRequest, "Unknown signature.")
		return
	}

	err = act(id, r.PostForm.Get("digest"), sess.Login)
	switch {
	case errors.Is(err, store.ErrNotFound):
		// Already handled, perhaps by another admin.
	case errors.Is(err, store.ErrStale):
		s.fail(w, r, http.StatusConflict, "This signature changed since the page was loaded. Nothing was changed; reload the page to review it again.")
		return
	case errors.Is(err, store.ErrConflict):
		s.fail(w, r, http.StatusConflict, "This account already has a different signature on file. Nothing was changed; resolve it in the data directory.")
		return
	case err != nil:
		slog.Error("updating a pending signature failed", "error", err)
		s.Alerts.Report(alert.StoreWrite, alert.Detail{Status: githubapp.StatusOf(err)})
		s.fail(w, r, http.StatusServiceUnavailable, "The change could not be saved. Please try again.")
		return
	default:
		s.Alerts.Resolve(alert.StoreWrite)
	}
	s.recheck(s.Checker.BlockedBy(id))
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}
