package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"time"

	"github.com/rotki/cla/internal/alert"
	"github.com/rotki/cla/internal/audit"
	"github.com/rotki/cla/internal/check"
	"github.com/rotki/cla/internal/config"
	"github.com/rotki/cla/internal/githubapp"
	"github.com/rotki/cla/internal/limits"
	"github.com/rotki/cla/internal/logging"
	"github.com/rotki/cla/internal/org"
	"github.com/rotki/cla/internal/reconcile"
	"github.com/rotki/cla/internal/records"
	"github.com/rotki/cla/internal/seal"
	"github.com/rotki/cla/internal/store"
	"github.com/rotki/cla/internal/version"
	"github.com/rotki/cla/internal/web"
	"github.com/rotki/cla/internal/webhook"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		port := os.Getenv("PORT")
		if port == "" {
			port = "4000"
		}
		resp, err := http.Get(fmt.Sprintf("http://localhost:%s/healthz", port))
		if err != nil || resp.StatusCode != http.StatusOK {
			os.Exit(1)
		}
		os.Exit(0)
	}

	slog.SetDefault(logging.New(os.Stdout, os.Getenv("LOG_LEVEL")))

	// Go follows the container's CPU limit on its own; the memory limit it
	// has to be told.
	if mem, err := limits.ApplyMemoryLimit("/sys/fs/cgroup"); err != nil {
		slog.Warn("could not apply the container memory limit", "error", err)
	} else {
		slog.Info("runtime limits", "gomaxprocs", runtime.GOMAXPROCS(0), "memory_limit_source", mem.Source,
			"container_memory_bytes", mem.Container, "go_memory_limit_bytes", mem.Limit)
	}
	slog.Info("starting", "version", version.Version, "git_sha", version.GitSHA)

	if err := run(); err != nil {
		slog.Error("fatal", "error", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	app := githubapp.New(cfg.AppID, cfg.AppPrivateKey, cfg.GitHubAPIURL)
	initCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	err = app.Init(initCtx, cfg.Org)
	cancel()
	if err != nil {
		return fmt.Errorf("finding the App installation on %s: %w", cfg.Org, err)
	}
	slog.Info("installation found", "org", cfg.Org, "installation_id", app.InstallationID(), "app", app.Slug())

	sealer, err := seal.New(cfg.AgeRecipient, cfg.AgeKeyID)
	if err != nil {
		return err
	}

	// The App never writes repository contents: signatures live in the data
	// directory, not on GitHub.
	gh := app.Client(githubapp.Scope{Permissions: map[string]string{
		"statuses":      "write",
		"pull_requests": "write",
		"contents":      "read",
		"members":       "read",
		"metadata":      "read",
	}})
	alerts := alert.New(cfg.DiscordWebhookURL)
	if cfg.DiscordWebhookURL == "" {
		slog.Warn("DISCORD_WEBHOOK_URL is not set: alerts only go to this log")
	}
	st := store.New(cfg.DataDir)
	agreement := store.NewAgreement(githubapp.NewPublicClient(cfg.GitHubAPIURL))
	directory := org.New(gh, cfg.Org)
	checker := check.NewChecker(gh, st, directory, check.Options{
		Owner:         cfg.Org,
		StatusContext: cfg.StatusContext,
		BaseURL:       cfg.BaseURL,
		BotLogin:      func() string { return app.Slug() + "[bot]" },
		NoComments:    !cfg.Comments,
	})
	queue := check.NewQueue(checker, alerts, app.Limits, 1000)
	sweeper := reconcile.New(gh, st, agreement, checker, queue, alerts, app.Limits, cfg.Org)

	hook := webhook.New(cfg.WebhookSecret, app.InstallationID, queue, alerts, func(repo string) {
		if err := sweeper.SweepRepo(ctx, repo); err != nil {
			slog.Error("sweeping a newly added repository failed", "repo", repo, "error", err)
		}
	})

	site, err := web.New(web.Deps{
		App: app,
		OAuth: &githubapp.OAuth{
			ClientID:     cfg.AppClientID,
			ClientSecret: cfg.AppClientSecret,
			RedirectURL:  cfg.BaseURL + "/oauth/callback",
			GitHubURL:    cfg.GitHubURL,
			APIURL:       cfg.GitHubAPIURL,
		},
		Store:      st,
		Agreement:  agreement,
		Directory:  directory,
		Sealer:     sealer,
		Checker:    checker,
		Queue:      queue,
		Alerts:     alerts,
		Limits:     app.Limits,
		Rechecker:  sweeper,
		Org:        cfg.Org,
		SessionKey: cfg.SessionKey,
		Secure:     cfg.SecureCookies,
	})
	if err != nil {
		return err
	}

	serverErr := make(chan error, 1)
	server := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           site.Handler(hook),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	// Nothing is checked before the signatures are loaded: with an empty
	// store everyone looks unsigned and no repo is excluded. The web server
	// already answers meanwhile (health, and 503 on /ready).
	go serve(server, serverErr)
	if err := waitForStore(ctx, st, alerts); err != nil {
		return shutdown(server, err)
	}
	if err := agreement.Warm(ctx, st.Config()); err != nil {
		slog.Error("loading the CLA text failed", "error", err)
	}

	// Alerts stop last, on their own context, so what the stopping work
	// reports still reaches Discord.
	alertCtx, stopAlerts := context.WithCancel(context.WithoutCancel(ctx))
	alertsDone := make(chan struct{})
	go func() {
		defer close(alertsDone)
		alerts.Run(alertCtx)
	}()

	var wg sync.WaitGroup
	wg.Go(func() { queue.Run(ctx, cfg.Workers) })
	wg.Go(func() { sweeper.Run(ctx, cfg.ReconcileInterval) })
	wg.Go(func() { anchor(ctx, st, alerts, cfg.AnchorInterval, cfg.AnchorDiscord, cfg.BackupDir) })
	if cfg.BackupDir != "" {
		wg.Go(func() { backups(ctx, cfg.DataDir, cfg.BackupDir, cfg.BackupInterval, cfg.BackupKeep, alerts) })
	} else {
		slog.Warn("BACKUP_DIR is not set, no backups are written")
	}

	select {
	case <-ctx.Done():
		slog.Info("shutting down")
	case err = <-serverErr:
		stop()
	}

	err = shutdown(server, err)
	wg.Wait()
	stopAlerts()
	<-alertsDone
	return err
}

func serve(server *http.Server, errs chan<- error) {
	slog.Info("listening", "addr", server.Addr)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		errs <- err
	}
}

// shutdownTime is how long requests in flight may take once a shutdown
// begins: a signing being saved has its own 30 s budget, but finishes in
// well under a second. Everything together stays inside the 30 s grace
// period docs/deploy.md asks Swarm for.
const shutdownTime = 20 * time.Second

func shutdown(server *http.Server, err error) error {
	ctx, cancel := context.WithTimeout(context.Background(), shutdownTime)
	defer cancel()
	if shutdownErr := server.Shutdown(ctx); shutdownErr != nil {
		slog.Error("HTTP server shutdown error", "error", shutdownErr)
	}
	return err
}

// anchorRetry is how soon an anchor that did not reach Discord is tried
// again.
const anchorRetry = 15 * time.Minute

// anchor logs the audit log's head at start and then every interval, whenever
// it moved, and with post also publishes it to the alert channel. The channel
// keeps a dated copy outside the server, so a log rewritten later no longer
// matches it; see cla-tool verify -anchor. Without post, the backup manifests
// carry the head off the host instead. The whole chain is checked first, and a
// posted head counts as published only once Discord accepted it.
//
// Each check also makes sure the log still holds the last head published
// (or, after a restart, the head in the newest backup manifest): a log
// rewritten or cut back to before it would otherwise be anchored anew without an alert.
func anchor(ctx context.Context, st *store.Store, alerts *alert.Notifier, interval time.Duration, post bool, backupDir string) {
	var published audit.Event
	if backupDir != "" {
		if m, ok, err := records.LatestManifest(backupDir); err == nil && ok && m.Events > 0 {
			published = audit.Event{Seq: int64(m.Events), Hash: m.Head}
		}
	}
	for {
		wait := interval
		held := ""
		chain, err := audit.Scan(filepath.Join(st.Dir(), filepath.FromSlash(store.AuditLog)), func(e audit.Event) error {
			if e.Seq == published.Seq {
				held = e.Hash
			}
			return nil
		})
		switch {
		case err != nil:
			slog.Error("the audit log chain is broken, no anchor published", "error", err)
			alerts.Report(alert.AuditBroken, alert.Detail{})
		case published.Seq > 0 && held != published.Hash:
			slog.Error("the audit log no longer holds the last anchored event: it was rewritten or cut back", "seq", published.Seq, "hash", published.Hash)
			alerts.Report(alert.AuditBroken, alert.Detail{})
		case chain.Events == 0 || chain.Head == published.Hash:
			alerts.Resolve(alert.AuditBroken)
		case !post:
			alerts.Resolve(alert.AuditBroken)
			slog.Info("audit anchor", "seq", chain.Events, "hash", chain.Head)
			published = audit.Event{Seq: chain.Events, Hash: chain.Head}
		default:
			alerts.Resolve(alert.AuditBroken)
			switch err := alerts.Anchor(ctx, chain.Events, chain.Head); {
			case errors.Is(err, alert.ErrNoWebhook):
				// Logged only; startup already warned.
				published = audit.Event{Seq: chain.Events, Hash: chain.Head}
			case err != nil:
				slog.Error("publishing the audit anchor failed", "error", err, "retry_in", anchorRetry)
				wait = min(interval, anchorRetry)
			default:
				published = audit.Event{Seq: chain.Events, Hash: chain.Head}
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

// backupRetry is how soon a failed backup is tried again.
const backupRetry = 15 * time.Minute

// backups writes a verified archive of the data directory into outDir every
// interval, for an outside job to encrypt and ship off the host. The first
// one is due an interval after the newest archive already there, so a
// restart does not add one. A failure is retried after backupRetry; failures
// and archives that failed verification are alerted, at most once an hour.
func backups(ctx context.Context, dataDir, outDir string, interval time.Duration, keep int, alerts *alert.Notifier) {
	var wait time.Duration
	if m, ok, err := records.LatestManifest(outDir); err != nil {
		slog.Error("reading the latest backup manifest failed", "error", err)
	} else if ok {
		wait = max(time.Until(m.Time.Add(interval)), 0)
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		wait = interval
		m, err := records.Backup(dataDir, outDir, time.Now(), keep)
		if err != nil {
			slog.Error("backup failed", "error", err, "retry_in", backupRetry)
			alerts.Report(alert.BackupFailed, alert.Detail{})
			wait = min(interval, backupRetry)
			continue
		}
		alerts.Resolve(alert.BackupFailed)
		if !m.OK {
			slog.Warn("backup written, but the data failed verification", "archive", m.Archive, "problems", m.Problems)
			alerts.Report(alert.BackupProblems, alert.Detail{Problems: m.Problems})
			continue
		}
		alerts.Resolve(alert.BackupProblems)
		slog.Info("backup written", "archive", m.Archive, "bytes", m.Bytes, "records", m.Records, "events", m.Events)
	}
}

// waitForStore retries the first load of the data directory, backing off
// from 5 s to a minute, until it succeeds or the service stops.
func waitForStore(ctx context.Context, st *store.Store, alerts *alert.Notifier) error {
	delay := 5 * time.Second
	for {
		err := st.Refresh(ctx)
		if err == nil {
			alerts.Resolve(alert.StoreRead)
			slog.Info("signatures loaded", "data_dir", st.Dir(), "audit_head", st.Head())
			return nil
		}
		slog.Error("loading the signatures failed, retrying", "error", err, "in", delay)
		alerts.Report(alert.StoreRead, alert.Detail{Status: githubapp.StatusOf(err)})
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
		}
		delay = min(delay*2, time.Minute)
	}
}
