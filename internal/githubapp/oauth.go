package githubapp

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// OAuth is the App's user login flow (GitHub App user access tokens) with PKCE.
type OAuth struct {
	ClientID     string
	ClientSecret string
	RedirectURL  string
	GitHubURL    string
	APIURL       string
	HTTP         *http.Client
}

// NewVerifier returns a PKCE code verifier and an OAuth state value.
func NewVerifier() (verifier, state string) {
	return randomToken(32), randomToken(16)
}

func randomToken(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// AuthorizeURL is where the user is sent to log in.
func (o *OAuth) AuthorizeURL(state, verifier string) string {
	challenge := sha256.Sum256([]byte(verifier))
	q := url.Values{
		"client_id":             {o.ClientID},
		"redirect_uri":          {o.RedirectURL},
		"state":                 {state},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(challenge[:])},
		"code_challenge_method": {"S256"},
		"allow_signup":          {"false"},
	}
	return o.GitHubURL + "/login/oauth/authorize?" + q.Encode()
}

// Exchange trades the callback code for a user access token.
func (o *OAuth) Exchange(ctx context.Context, code, verifier string) (string, error) {
	form := url.Values{
		"client_id":     {o.ClientID},
		"client_secret": {o.ClientSecret},
		"code":          {code},
		"redirect_uri":  {o.RedirectURL},
		"code_verifier": {verifier},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, o.GitHubURL+"/login/oauth/access_token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := o.HTTP
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("oauth token exchange: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	var out struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", fmt.Errorf("oauth token exchange: decoding response: %w", err)
	}
	if resp.StatusCode != http.StatusOK || out.AccessToken == "" {
		// The error code is a fixed identifier like bad_verification_code.
		return "", fmt.Errorf("oauth token exchange failed: status %d, %s", resp.StatusCode, out.Error)
	}
	return out.AccessToken, nil
}

// Revoke invalidates a user access token, so it is useless after the login
// has read what it needs.
func (o *OAuth) Revoke(ctx context.Context, token string) error {
	body, err := json.Marshal(map[string]string{"access_token": token})
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, o.APIURL+"/applications/"+o.ClientID+"/token", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.SetBasicAuth(o.ClientID, o.ClientSecret)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")
	client := o.HTTP
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return redactURL(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusNotFound {
		return fmt.Errorf("revoking the token: status %d", resp.StatusCode)
	}
	return nil
}

// redactURL keeps request URLs out of transport errors.
func redactURL(err error) error {
	var uerr *url.Error
	if errors.As(err, &uerr) {
		return uerr.Err
	}
	return err
}

// User is the logged-in account.
type User struct {
	ID    int64  `json:"id"`
	Login string `json:"login"`
	Name  string `json:"name"`
}

// FetchUser returns the account and its verified email addresses, primary
// first. It needs the App's "email addresses: read" account permission.
func FetchUser(ctx context.Context, c *Client) (User, []string, error) {
	// The two calls are independent, so they go out together: a login
	// waits for one round trip to GitHub, not two.
	var user User
	var emails []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}
	var userErr error
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, userErr = c.Do(ctx, http.MethodGet, "/user", nil, &user)
	}()
	_, emailsErr := c.Do(ctx, http.MethodGet, "/user/emails?per_page=100", nil, &emails)
	<-done
	if err := errors.Join(userErr, emailsErr); err != nil {
		return user, nil, err
	}
	var verified []string
	for _, e := range emails {
		if !e.Verified {
			continue
		}
		if e.Primary {
			verified = append([]string{e.Email}, verified...)
		} else {
			verified = append(verified, e.Email)
		}
	}
	return user, verified, nil
}
