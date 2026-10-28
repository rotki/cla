// Package alert reports operational problems to a Discord webhook.
//
// Two rules shape it. Messages come from fixed templates filled with a repo,
// a PR number and an HTTP status only, never with error text, so no personal
// data can leak into a channel. And each kind of problem sends at most one
// message per window: the first occurrence goes out at once, repeats are
// counted and summarised when the window closes, and a recovery is announced
// once.
package alert

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"sync"
	"time"
)

type Kind string

const (
	CheckFailed    Kind = "check_failed"
	StoreRead      Kind = "store_read"
	StoreWrite     Kind = "store_write"
	BadSignature   Kind = "bad_webhook_signature"
	ReconcileError Kind = "reconcile_failed"
	RateLimited    Kind = "rate_limited"
	BackupFailed   Kind = "backup_failed"
	BackupProblems Kind = "backup_unverified"
	AuditBroken    Kind = "audit_broken"
	NoAccess       Kind = "no_access"
)

var titles = map[Kind]string{
	CheckFailed:    "CLA check failed",
	StoreRead:      "Reading the signatures data directory failed",
	StoreWrite:     "Writing to the signatures data directory failed",
	BadSignature:   "Webhook with an invalid signature rejected",
	ReconcileError: "Reconcile sweep failed",
	RateLimited:    "GitHub rate limit reached, work deferred until it resets",
	BackupFailed:   "Backup of the signatures failed or was skipped, retrying",
	BackupProblems: "Backup written, but the data failed verification: run cla-tool verify",
	AuditBroken:    "The audit log chain is broken, no anchor published: run cla-tool verify",
	NoAccess:       "The App has no access to a repository it was asked to check: it is not installed there, or a permission is missing. Check the App's installation and permissions",
}

// Detail is everything a message may carry. Keep it free of personal data.
type Detail struct {
	Repo     string
	PR       int
	Status   int
	Problems int
	// Call is what was being done, from githubapp.Call: a fixed phrase.
	Call string
}

func (d Detail) String() string {
	s := ""
	if d.Repo != "" {
		s = d.Repo
		if d.PR > 0 {
			s += fmt.Sprintf("#%d", d.PR)
		}
	}
	if d.Call != "" {
		if s != "" {
			s += " "
		}
		s += "while " + d.Call
	}
	if d.Status > 0 {
		if s != "" {
			s += " "
		}
		// The status in words too: a bare "403" says little to whoever reads
		// the channel.
		if text := http.StatusText(d.Status); text != "" {
			s += fmt.Sprintf("(GitHub %d %s)", d.Status, text)
		} else {
			s += fmt.Sprintf("(GitHub %d)", d.Status)
		}
	}
	if d.Problems > 0 {
		if s != "" {
			s += " "
		}
		s += fmt.Sprintf("(%d problems)", d.Problems)
	}
	return s
}

type state struct {
	failing     bool
	windowStart time.Time
	suppressed  int
}

type Notifier struct {
	url    string
	client *http.Client
	window time.Duration
	now    func() time.Time
	send   func(ctx context.Context, message string) error

	mu    sync.Mutex
	kinds map[Kind]*state

	// outbox decouples callers from Discord: Report and Resolve never wait on
	// the network, Run does the sending.
	outbox chan string
}

// New returns a notifier. With an empty webhookURL messages are only logged.
func New(webhookURL string) *Notifier {
	n := &Notifier{
		url:    webhookURL,
		client: &http.Client{Timeout: 10 * time.Second},
		window: time.Hour,
		now:    time.Now,
		kinds:  map[Kind]*state{},
		outbox: make(chan string, 64),
	}
	n.send = n.post
	return n
}

// Report records one occurrence of a problem.
func (n *Notifier) Report(kind Kind, d Detail) {
	n.mu.Lock()
	s := n.kinds[kind]
	if s == nil {
		s = &state{}
		n.kinds[kind] = s
	}
	now := n.now()
	if s.failing && now.Sub(s.windowStart) < n.window {
		s.suppressed++
		n.mu.Unlock()
		return
	}
	s.failing = true
	s.windowStart = now
	s.suppressed = 0
	n.mu.Unlock()

	msg := fmt.Sprintf("**%s**", titles[kind])
	if detail := d.String(); detail != "" {
		msg += " " + detail
	}
	n.deliver(msg)
}

// Resolve marks a kind as working again. It announces the recovery once, if
// the kind had been failing.
func (n *Notifier) Resolve(kind Kind) {
	n.mu.Lock()
	s := n.kinds[kind]
	if s == nil || !s.failing {
		n.mu.Unlock()
		return
	}
	suppressed := s.suppressed
	delete(n.kinds, kind)
	n.mu.Unlock()

	msg := fmt.Sprintf("**Recovered:** %s", titles[kind])
	if suppressed > 0 {
		msg += fmt.Sprintf(" (%d more failures since the last message)", suppressed)
	}
	n.deliver(msg)
}

// Flush summarises kinds whose window has closed with suppressed repeats. A
// kind that keeps failing gets one summary per window.
func (n *Notifier) Flush() {
	n.mu.Lock()
	now := n.now()
	var messages []string
	for kind, s := range n.kinds {
		if !s.failing || now.Sub(s.windowStart) < n.window {
			continue
		}
		if s.suppressed > 0 {
			messages = append(messages, fmt.Sprintf("**%s** %d more times in the last hour", titles[kind], s.suppressed))
		}
		s.windowStart = now
		s.suppressed = 0
	}
	n.mu.Unlock()

	for _, m := range messages {
		n.deliver(m)
	}
}

// Run sends queued messages and flushes summaries until ctx is done.
func (n *Notifier) Run(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			n.flushOutbox(flushTime)
			return
		case m := <-n.outbox:
			n.post1(m)
		case <-ticker.C:
			n.Flush()
		}
	}
}

// flushTime bounds how long a stopping service spends sending what is left.
const flushTime = 5 * time.Second

// flushOutbox sends what is still queued, until the outbox is empty or limit
// has passed, so an alert raised just before a shutdown is not lost.
func (n *Notifier) flushOutbox(limit time.Duration) {
	deadline := time.Now().Add(limit)
	for time.Now().Before(deadline) {
		select {
		case m := <-n.outbox:
			n.post1(m)
		default:
			return
		}
	}
}

// deliver logs a message and queues it for Discord without blocking. When
// the outbox is full the message is only logged; alerts are best effort.
func (n *Notifier) deliver(message string) {
	slog.Warn("alert", "message", message)
	if n.url == "" {
		return
	}
	select {
	case n.outbox <- message:
	default:
		slog.Error("alert outbox full, message dropped")
	}
}

// ErrNoWebhook is returned by Anchor when no Discord webhook is set.
var ErrNoWebhook = errors.New("no Discord webhook configured")

// Anchor publishes the audit log's head and waits for Discord to accept it,
// so the caller knows whether the anchor really left the host. It is a
// record, not a problem, so it bypasses the windows and the outbox; it
// carries only a sequence number and a hash.
func (n *Notifier) Anchor(ctx context.Context, seq int64, hash string) error {
	slog.Info("audit anchor", "seq", seq, "hash", hash)
	if n.url == "" {
		return ErrNoWebhook
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := n.send(ctx, fmt.Sprintf("**Audit log anchor** seq %d %#q", seq, hash)); err != nil {
		return redact(err)
	}
	return nil
}

func (n *Notifier) post1(message string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := n.send(ctx, message); err != nil {
		slog.Error("sending alert failed", "error", redact(err))
	}
}

// redact drops the request URL from a transport error: the webhook URL
// carries its token.
func redact(err error) error {
	var uerr *url.Error
	if errors.As(err, &uerr) {
		return uerr.Err
	}
	return err
}

func (n *Notifier) post(ctx context.Context, message string) error {
	body, err := json.Marshal(map[string]any{
		"content":          message,
		"allowed_mentions": map[string]any{"parse": []string{}},
	})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := n.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("discord webhook returned %d", resp.StatusCode)
	}
	return nil
}
