package config

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeFile(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func testKeyPEM(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
}

// setBase sets a complete, valid environment using plain env values.
func setBase(t *testing.T) {
	t.Helper()
	t.Setenv("GITHUB_ORG", "rotki")
	t.Setenv("BASE_URL", "https://cla.rotki.com/")
	t.Setenv("GITHUB_APP_ID", "1234")
	t.Setenv("GITHUB_APP_PRIVATE_KEY", testKeyPEM(t))
	t.Setenv("GITHUB_APP_CLIENT_ID", "Iv1.abc")
	t.Setenv("GITHUB_APP_CLIENT_SECRET", "client-secret")
	t.Setenv("GITHUB_WEBHOOK_SECRET", "webhook-secret")
	t.Setenv("SESSION_KEY", strings.Repeat("s", 32))
	t.Setenv("AGE_RECIPIENT", "age1qyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqs3290gq")
	t.Setenv("AGE_KEY_ID", "2026-01")
	for _, name := range []string{"GITHUB_APP_PRIVATE_KEY", "GITHUB_APP_CLIENT_SECRET", "GITHUB_WEBHOOK_SECRET", "SESSION_KEY", "DISCORD_WEBHOOK_URL"} {
		t.Setenv(name+"_FILE", "")
	}
}

func TestLoadFromEnv(t *testing.T) {
	setBase(t)
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.BaseURL != "https://cla.rotki.com" || !cfg.SecureCookies || cfg.AppClientSecret != "client-secret" || string(cfg.WebhookSecret) != "webhook-secret" {
		t.Fatalf("config %+v", cfg)
	}
	if cfg.Org != "rotki" || cfg.StatusContext != "license/cla" || cfg.Workers != 4 || !cfg.Comments || cfg.AnchorDiscord {
		t.Fatalf("defaults %+v", cfg)
	}
}

func TestLoadFromSecretFiles(t *testing.T) {
	setBase(t)
	files := map[string]string{
		"GITHUB_APP_PRIVATE_KEY":   testKeyPEM(t),
		"GITHUB_APP_CLIENT_SECRET": "file-client-secret\n",
		"GITHUB_WEBHOOK_SECRET":    "file-webhook-secret\r\n",
		"SESSION_KEY":              strings.Repeat("f", 40) + "\n",
		"DISCORD_WEBHOOK_URL":      "https://discord.com/api/webhooks/1/token\n",
	}
	for name, content := range files {
		t.Setenv(name, "")
		t.Setenv(name+"_FILE", writeFile(t, strings.ToLower(name), content))
	}

	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AppClientSecret != "file-client-secret" || string(cfg.WebhookSecret) != "file-webhook-secret" {
		t.Fatalf("trailing newlines kept: %q %q", cfg.AppClientSecret, cfg.WebhookSecret)
	}
	if string(cfg.SessionKey) != strings.Repeat("f", 40) || cfg.DiscordWebhookURL != "https://discord.com/api/webhooks/1/token" {
		t.Fatalf("config %+v", cfg)
	}
}

func TestSecretRejectsBothSources(t *testing.T) {
	setBase(t)
	t.Setenv("GITHUB_WEBHOOK_SECRET_FILE", writeFile(t, "w", "other"))
	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), "not both") {
		t.Fatalf("got %v", err)
	}
	if strings.Contains(err.Error(), "webhook-secret") || strings.Contains(err.Error(), "other") {
		t.Fatalf("error leaks a secret: %v", err)
	}
}

func TestSecretFileErrors(t *testing.T) {
	setBase(t)
	t.Setenv("SESSION_KEY", "")
	t.Setenv("SESSION_KEY_FILE", filepath.Join(t.TempDir(), "missing"))
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "SESSION_KEY_FILE") {
		t.Fatalf("missing file: %v", err)
	}

	t.Setenv("SESSION_KEY_FILE", writeFile(t, "big", strings.Repeat("x", maxSecretSize+1)))
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("oversized file: %v", err)
	}

	t.Setenv("SESSION_KEY_FILE", writeFile(t, "short", "too-short\n"))
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "at least 32 bytes") {
		t.Fatalf("short key: %v", err)
	}
}

func TestSwitches(t *testing.T) {
	setBase(t)
	t.Setenv("PR_COMMENTS", "false")
	t.Setenv("AUDIT_ANCHOR_DISCORD", "true")
	t.Setenv("DISCORD_WEBHOOK_URL", "")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "needs DISCORD_WEBHOOK_URL") {
		t.Fatalf("anchors to Discord without a webhook: %v", err)
	}
	t.Setenv("DISCORD_WEBHOOK_URL", "https://discord.com/api/webhooks/1/token")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Comments || !cfg.AnchorDiscord {
		t.Fatalf("switches %+v", cfg)
	}
	t.Setenv("PR_COMMENTS", "maybe")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "PR_COMMENTS") {
		t.Fatalf("got %v", err)
	}
}

func TestLoadRequiresSecrets(t *testing.T) {
	for _, name := range []string{"GITHUB_ORG", "GITHUB_APP_PRIVATE_KEY", "GITHUB_APP_CLIENT_SECRET", "GITHUB_WEBHOOK_SECRET", "SESSION_KEY"} {
		t.Run(name, func(t *testing.T) {
			setBase(t)
			t.Setenv(name, "")
			if _, err := Load(); err == nil || !strings.Contains(err.Error(), name) {
				t.Fatalf("got %v", err)
			}
		})
	}
}
