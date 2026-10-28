// Package webhook receives GitHub App events, verifies them and queues work.
// It answers quickly and never does the checking itself.
package webhook

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"

	"github.com/rotki/cla/internal/alert"
	"github.com/rotki/cla/internal/check"
)

// maxPayload caps what is read before the signature is checked. GitHub
// documents only its own 25 MB cap and no receiver limit. The events
// subscribed to are small: a pull_request delivery on rotki/rotki is about
// 28 KB, and even a description at GitHub's 65,536 character limit stays
// near 300 KB. 1 MB leaves a wide margin, while reading 25 MB per
// unauthenticated request would let anyone exhaust memory.
const maxPayload = 1 << 20

// Queue is the part of check.Queue the handler needs.
type Queue interface {
	Enqueue(job check.Job) bool
}

type Handler struct {
	secret         []byte
	installationID func() int64
	queue          Queue
	alerts         *alert.Notifier
	reposChanged   func(added []string)

	mu         sync.Mutex
	deliveries map[string]bool
	order      []string
}

// New returns the webhook handler. reposChanged is called when repositories
// are added to or removed from the installation, with the added ones, so the
// list of repositories to check is updated and their open pull requests get
// checked.
func New(secret []byte, installationID func() int64, queue Queue, alerts *alert.Notifier, reposChanged func(added []string)) *Handler {
	return &Handler{
		secret:         secret,
		installationID: installationID,
		queue:          queue,
		alerts:         alerts,
		reposChanged:   reposChanged,
		deliveries:     map[string]bool{},
	}
}

// Valid checks the X-Hub-Signature-256 header against the payload.
func Valid(secret, payload []byte, header string) bool {
	sig, ok := strings.CutPrefix(header, "sha256=")
	if !ok {
		return false
	}
	got, err := hex.DecodeString(sig)
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write(payload)
	return hmac.Equal(got, mac.Sum(nil))
}

type event struct {
	Action       string `json:"action"`
	Installation struct {
		ID int64 `json:"id"`
	} `json:"installation"`
	Repository struct {
		Name    string `json:"name"`
		Private bool   `json:"private"`
	} `json:"repository"`
	PullRequest struct {
		Number int `json:"number"`
	} `json:"pull_request"`
	// Changes is set on an edited event; Base when the base branch moved.
	Changes struct {
		Base *struct{} `json:"base"`
	} `json:"changes"`
	MergeGroup struct {
		HeadSHA string `json:"head_sha"`
	} `json:"merge_group"`
	RepositoriesAdded []struct {
		Name string `json:"name"`
	} `json:"repositories_added"`
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	payload, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxPayload))
	if err != nil {
		w.WriteHeader(http.StatusRequestEntityTooLarge)
		return
	}
	if !Valid(h.secret, payload, r.Header.Get("X-Hub-Signature-256")) {
		// Not resolved by a valid delivery: that would let anyone re-trigger
		// the alert after every real webhook. The hourly window closes it.
		h.alerts.Report(alert.BadSignature, alert.Detail{})
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	if h.seen(r.Header.Get("X-GitHub-Delivery")) {
		w.WriteHeader(http.StatusOK)
		return
	}

	var ev event
	if err := json.Unmarshal(payload, &ev); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if ev.Installation.ID != h.installationID() {
		// Only the org installation is served.
		w.WriteHeader(http.StatusAccepted)
		return
	}

	h.dispatch(r.Header.Get("X-GitHub-Event"), ev)
	w.WriteHeader(http.StatusAccepted)
}

func (h *Handler) dispatch(kind string, ev event) {
	if ev.Repository.Private && (kind == "pull_request" || kind == "merge_group") {
		// Private repositories are never checked, as with cla-assistant:
		// only the team can contribute there.
		return
	}
	switch kind {
	case "pull_request":
		ref := check.Ref{Repo: ev.Repository.Name, Number: ev.PullRequest.Number}
		switch ev.Action {
		case "opened", "reopened", "synchronize":
			h.queue.Enqueue(check.Job{Ref: ref})
		case "edited":
			// A new base changes which commits the pull request holds, and
			// so its authors, without a new head commit.
			if ev.Changes.Base != nil {
				h.queue.Enqueue(check.Job{Ref: ref})
			}
		case "closed":
			h.queue.Enqueue(check.Job{Ref: ref, Closed: true})
		}
	case "merge_group":
		if ev.Action == "checks_requested" && ev.MergeGroup.HeadSHA != "" {
			h.queue.Enqueue(check.Job{Ref: check.Ref{Repo: ev.Repository.Name}, MergeSHA: ev.MergeGroup.HeadSHA})
		}
	case "installation_repositories":
		if (ev.Action == "added" || ev.Action == "removed") && h.reposChanged != nil {
			names := make([]string, 0, len(ev.RepositoriesAdded))
			for _, repo := range ev.RepositoriesAdded {
				names = append(names, repo.Name)
			}
			// The added ones are swept one after another, as GitHub asks:
			// adding many repos at once must not fire a burst of searches.
			go h.reposChanged(names)
		}
	case "ping":
		slog.Info("webhook ping received")
	}
}

// seen remembers the last deliveries, so a redelivery is not processed twice.
func (h *Handler) seen(id string) bool {
	if id == "" {
		return false
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.deliveries[id] {
		return true
	}
	h.deliveries[id] = true
	h.order = append(h.order, id)
	if len(h.order) > 2000 {
		delete(h.deliveries, h.order[0])
		h.order = h.order[1:]
	}
	return false
}
