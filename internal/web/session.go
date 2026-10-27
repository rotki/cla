package web

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	sessionCookie = "cla_session"
	oauthCookie   = "cla_oauth"
	sessionTTL    = 15 * time.Minute
	oauthTTL      = 10 * time.Minute
)

// session is the logged-in user, kept entirely in an encrypted cookie. The
// service stores no session state and never keeps the user's GitHub token.
type session struct {
	ID     int64    `json:"id"`
	Login  string   `json:"login"`
	Name   string   `json:"name"`
	Emails []string `json:"emails"`
	CSRF   string   `json:"csrf"`
	Exp    int64    `json:"exp"`
}

// oauthState carries the PKCE verifier and where to return after login.
type oauthState struct {
	State    string `json:"state"`
	Verifier string `json:"verifier"`
	Return   string `json:"return"`
	Exp      int64  `json:"exp"`
}

type cookies struct {
	key    []byte
	secure bool
	now    func() time.Time
}

// encode encrypts and authenticates v with AES-256-GCM for one purpose, so
// a cookie of one kind cannot be replayed as another. Encrypted, not only
// signed: a session holds the signer's name and verified emails, which a
// stolen cookie must not reveal.
func (c cookies) encode(purpose string, v any) (string, error) {
	payload, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	aead, err := c.aead()
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(aead.Seal(nonce, nonce, payload, []byte(purpose))), nil
}

func (c cookies) decode(purpose, value string, v any) error {
	data, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return errors.New("malformed cookie")
	}
	aead, err := c.aead()
	if err != nil {
		return err
	}
	if len(data) < aead.NonceSize() {
		return errors.New("malformed cookie")
	}
	payload, err := aead.Open(nil, data[:aead.NonceSize()], data[aead.NonceSize():], []byte(purpose))
	if err != nil {
		return errors.New("bad cookie")
	}
	return json.Unmarshal(payload, v)
}

// aead derives the cookie cipher from SESSION_KEY.
func (c cookies) aead() (cipher.AEAD, error) {
	m := hmac.New(sha256.New, c.key)
	m.Write([]byte("cla cookie encryption v1"))
	block, err := aes.NewCipher(m.Sum(nil))
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// cookieName adds the __Host- prefix when cookies are Secure: the browser
// then takes the cookie only from this exact host, over HTTPS, with Path=/
// and no Domain, so another subdomain cannot plant or overwrite it (a
// planted session would let a victim sign while logged in as an attacker).
func (c cookies) cookieName(name string) string {
	if c.secure {
		return "__Host-" + name
	}
	return name
}

func (c cookies) get(r *http.Request, name string) (*http.Cookie, error) {
	return r.Cookie(c.cookieName(name))
}

func (c cookies) set(w http.ResponseWriter, name, value string, ttl time.Duration) {
	http.SetCookie(w, &http.Cookie{
		Name:     c.cookieName(name),
		Value:    value,
		Path:     "/",
		MaxAge:   int(ttl.Seconds()),
		HttpOnly: true,
		Secure:   c.secure,
		SameSite: http.SameSiteLaxMode,
	})
}

func (c cookies) clear(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{
		Name:     c.cookieName(name),
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   c.secure,
		SameSite: http.SameSiteLaxMode,
	})
}

func (c cookies) setSession(w http.ResponseWriter, s session) error {
	s.Exp = c.now().Add(sessionTTL).Unix()
	value, err := c.encode(sessionCookie, s)
	if err != nil {
		return err
	}
	c.set(w, sessionCookie, value, sessionTTL)
	return nil
}

// session returns the logged-in user, or nil.
func (c cookies) session(r *http.Request) *session {
	ck, err := c.get(r, sessionCookie)
	if err != nil {
		return nil
	}
	var s session
	if err := c.decode(sessionCookie, ck.Value, &s); err != nil || c.now().Unix() > s.Exp {
		return nil
	}
	return &s
}

func newToken() string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// returnPaths are the only pages a login may return to.
var returnPaths = map[string]bool{"/": true, "/sign": true, "/admin": true}

// safeReturn keeps post-login redirects on this site. Rather than guess every
// way a browser can read a path as another host (control characters it
// strips, backslashes it turns into slashes), it accepts only a known page
// with an optional query and falls back to /sign.
func safeReturn(p string) string {
	for _, r := range p {
		if r < 0x20 || r == 0x7f || r == '\\' {
			return "/sign"
		}
	}
	u, err := url.Parse(p)
	if err != nil || u.Scheme != "" || u.Host != "" || u.User != nil || u.Fragment != "" || !returnPaths[u.Path] || strings.HasPrefix(p, "//") {
		return "/sign"
	}
	return u.RequestURI()
}
