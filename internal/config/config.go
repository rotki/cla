// Package config loads the service's settings from the environment.
//
// Secrets and deployment settings live here. Settings that maintainers change
// at runtime (allowlist, exempt team, pinned CLA revision) live in config.json
// in the data directory instead, see store.RepoConfig.
package config

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Port    string
	BaseURL string

	Org           string
	DataDir       string
	StatusContext string
	Comments      bool

	AppID             int64
	AppPrivateKey     *rsa.PrivateKey
	AppClientID       string
	AppClientSecret   string
	WebhookSecret     []byte
	SessionKey        []byte
	AgeRecipient      string
	AgeKeyID          string
	DiscordWebhookURL string
	ReconcileInterval time.Duration
	AnchorInterval    time.Duration
	AnchorDiscord     bool
	BackupDir         string
	BackupInterval    time.Duration
	BackupKeep        int
	Workers           int
	GitHubAPIURL      string
	GitHubURL         string
	SecureCookies     bool
}

func Load() (*Config, error) {
	cfg := &Config{
		Port:              envOr("PORT", "4000"),
		BaseURL:           strings.TrimRight(os.Getenv("BASE_URL"), "/"),
		Org:               os.Getenv("GITHUB_ORG"),
		DataDir:           envOr("DATA_DIR", "/data"),
		BackupDir:         os.Getenv("BACKUP_DIR"),
		StatusContext:     envOr("STATUS_CONTEXT", "license/cla"),
		AppClientID:       os.Getenv("GITHUB_APP_CLIENT_ID"),
		AppClientSecret:   os.Getenv("GITHUB_APP_CLIENT_SECRET"),
		AgeRecipient:      strings.TrimSpace(os.Getenv("AGE_RECIPIENT")),
		AgeKeyID:          os.Getenv("AGE_KEY_ID"),
		DiscordWebhookURL: os.Getenv("DISCORD_WEBHOOK_URL"),
		GitHubAPIURL:      strings.TrimRight(envOr("GITHUB_API_URL", "https://api.github.com"), "/"),
		GitHubURL:         strings.TrimRight(envOr("GITHUB_URL", "https://github.com"), "/"),
	}

	if cfg.Org == "" {
		return nil, errors.New("GITHUB_ORG is required: the GitHub organization this service works for")
	}

	if port, err := strconv.Atoi(cfg.Port); err != nil || port < 1 || port > 65535 {
		return nil, fmt.Errorf("PORT must be a valid port number (1-65535), got %q", cfg.Port)
	}

	base, err := url.Parse(cfg.BaseURL)
	if cfg.BaseURL == "" || err != nil || base.Scheme == "" || base.Host == "" {
		return nil, errors.New("BASE_URL must be an absolute URL, e.g. https://cla.example.org")
	}
	cfg.SecureCookies = base.Scheme == "https"

	appID, err := strconv.ParseInt(os.Getenv("GITHUB_APP_ID"), 10, 64)
	if err != nil || appID <= 0 {
		return nil, errors.New("GITHUB_APP_ID is required")
	}
	cfg.AppID = appID

	pemKey, err := Secret("GITHUB_APP_PRIVATE_KEY")
	if err != nil {
		return nil, err
	}
	if pemKey == "" {
		return nil, errors.New("GITHUB_APP_PRIVATE_KEY_FILE or GITHUB_APP_PRIVATE_KEY is required")
	}
	if cfg.AppPrivateKey, err = ParsePrivateKey([]byte(pemKey)); err != nil {
		return nil, err
	}

	if cfg.AppClientSecret, err = Secret("GITHUB_APP_CLIENT_SECRET"); err != nil {
		return nil, err
	}
	if cfg.AppClientID == "" || cfg.AppClientSecret == "" {
		return nil, errors.New("GITHUB_APP_CLIENT_ID and GITHUB_APP_CLIENT_SECRET (or _FILE) are required")
	}

	webhookSecret, err := Secret("GITHUB_WEBHOOK_SECRET")
	if err != nil {
		return nil, err
	}
	if webhookSecret == "" {
		return nil, errors.New("GITHUB_WEBHOOK_SECRET (or _FILE) is required")
	}
	cfg.WebhookSecret = []byte(webhookSecret)

	sessionKey, err := Secret("SESSION_KEY")
	if err != nil {
		return nil, err
	}
	if len(sessionKey) < 32 {
		return nil, errors.New("SESSION_KEY (or _FILE) must be at least 32 bytes")
	}
	cfg.SessionKey = []byte(sessionKey)

	// A Discord webhook URL carries its own token, so it is a secret too.
	if cfg.DiscordWebhookURL, err = Secret("DISCORD_WEBHOOK_URL"); err != nil {
		return nil, err
	}

	if !strings.HasPrefix(cfg.AgeRecipient, "age1") {
		return nil, errors.New("AGE_RECIPIENT must be an age public key (age1...)")
	}
	if cfg.AgeKeyID == "" {
		return nil, errors.New("AGE_KEY_ID is required, it is stored with each record to name the key that sealed it")
	}

	cfg.ReconcileInterval, err = time.ParseDuration(envOr("RECONCILE_INTERVAL", "30m"))
	if err != nil || cfg.ReconcileInterval < time.Minute {
		return nil, errors.New("RECONCILE_INTERVAL must be a duration of at least 1m")
	}

	cfg.AnchorInterval, err = time.ParseDuration(envOr("AUDIT_ANCHOR_INTERVAL", "24h"))
	if err != nil || cfg.AnchorInterval < time.Minute {
		return nil, errors.New("AUDIT_ANCHOR_INTERVAL must be a duration of at least 1m")
	}
	cfg.Comments, err = strconv.ParseBool(envOr("PR_COMMENTS", "true"))
	if err != nil {
		return nil, errors.New("PR_COMMENTS must be true or false")
	}

	// Anchors always go to the log; posting them to Discord as well is opt-in,
	// since an active log means a message a day in the alert channel.
	cfg.AnchorDiscord, err = strconv.ParseBool(envOr("AUDIT_ANCHOR_DISCORD", "false"))
	if err != nil {
		return nil, errors.New("AUDIT_ANCHOR_DISCORD must be true or false")
	}
	if cfg.AnchorDiscord && cfg.DiscordWebhookURL == "" {
		return nil, errors.New("AUDIT_ANCHOR_DISCORD needs DISCORD_WEBHOOK_URL (or _FILE)")
	}

	cfg.BackupInterval, err = time.ParseDuration(envOr("BACKUP_INTERVAL", "24h"))
	if err != nil || cfg.BackupInterval < time.Hour {
		return nil, errors.New("BACKUP_INTERVAL must be a duration of at least 1h")
	}
	cfg.BackupKeep, err = strconv.Atoi(envOr("BACKUP_KEEP", "2"))
	if err != nil || cfg.BackupKeep < 1 {
		return nil, errors.New("BACKUP_KEEP must be a positive integer")
	}

	cfg.Workers, err = strconv.Atoi(envOr("WORKERS", "4"))
	if err != nil || cfg.Workers < 1 {
		return nil, errors.New("WORKERS must be a positive integer")
	}

	return cfg, nil
}

// maxSecretSize bounds what is read from a secret file; the largest secret,
// a PEM private key, is a few kilobytes.
const maxSecretSize = 64 << 10

// Secret reads a secret from NAME_FILE (a mounted secret such as
// /run/secrets/name, the Docker convention) or from NAME. Setting both is an
// error rather than a silent choice. A file's trailing newline is dropped.
// Errors never include the secret's value.
func Secret(name string) (string, error) {
	value, path := os.Getenv(name), os.Getenv(name+"_FILE")
	if path == "" {
		return value, nil
	}
	if value != "" {
		return "", fmt.Errorf("set either %s or %s_FILE, not both", name, name)
	}
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("reading %s_FILE: %w", name, err)
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, maxSecretSize+1))
	if err != nil {
		return "", fmt.Errorf("reading %s_FILE: %w", name, err)
	}
	if len(data) > maxSecretSize {
		return "", fmt.Errorf("%s_FILE is larger than %d bytes", name, maxSecretSize)
	}
	return strings.TrimRight(string(data), "\r\n"), nil
}

// ParsePrivateKey accepts the PKCS#1 PEM GitHub generates, and PKCS#8.
func ParsePrivateKey(data []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("GitHub App private key is not PEM encoded")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing GitHub App private key: %w", err)
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("GitHub App private key is not an RSA key")
	}
	return key, nil
}

func envOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}
