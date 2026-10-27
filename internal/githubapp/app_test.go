package githubapp

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestJWT(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	a := New(1234, key, "https://api.github.com")
	now := time.Unix(1_800_000_000, 0)
	a.now = func() time.Time { return now }

	token, err := a.JWT()
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token has %d parts", len(parts))
	}

	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	if err := rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, digest[:], sig); err != nil {
		t.Fatalf("signature does not verify: %v", err)
	}

	payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var claims struct {
		Iat int64  `json:"iat"`
		Exp int64  `json:"exp"`
		Iss string `json:"iss"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatal(err)
	}
	if claims.Iss != "1234" || claims.Iat != now.Unix()-60 || claims.Exp-claims.Iat > 600 {
		t.Fatalf("claims %+v", claims)
	}
}

func TestTokensAreScopedAndCached(t *testing.T) {
	var requests []Scope
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var s Scope
		_ = json.NewDecoder(r.Body).Decode(&s)
		requests = append(requests, s)
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"token":"t%d","expires_at":"2099-01-01T00:00:00Z"}`, len(requests))
	}))
	defer srv.Close()

	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	a := New(1, key, srv.URL)
	store := Scope{Repositories: []string{"some-repo"}, Permissions: map[string]string{"contents": "write"}}
	checks := Scope{Permissions: map[string]string{"contents": "read"}}

	t1, _ := a.Token(context.Background(), store)
	t2, _ := a.Token(context.Background(), checks)
	t3, _ := a.Token(context.Background(), store)
	if t1 == t2 || t1 != t3 || len(requests) != 2 {
		t.Fatalf("tokens %s %s %s after %d requests", t1, t2, t3, len(requests))
	}
	if requests[0].Repositories[0] != "some-repo" || requests[0].Permissions["contents"] != "write" {
		t.Fatalf("store token requested as %+v", requests[0])
	}
}

func TestNextLink(t *testing.T) {
	link := `<https://api.github.com/repos/rotki/rotki/pulls?page=2&per_page=100>; rel="next", <https://api.github.com/repos/rotki/rotki/pulls?page=9>; rel="last"`
	if got := nextLink(link, "https://api.github.com"); got != "/repos/rotki/rotki/pulls?page=2&per_page=100" {
		t.Fatalf("got %q", got)
	}
	if got := nextLink(`<https://api.github.com/x?page=1>; rel="prev"`, "https://api.github.com"); got != "" {
		t.Fatalf("got %q", got)
	}
}

func TestAuthorizeURLUsesPKCE(t *testing.T) {
	o := &OAuth{ClientID: "Iv1.abc", RedirectURL: "https://cla.rotki.com/oauth/callback", GitHubURL: "https://github.com"}
	u := o.AuthorizeURL("state1", "verifier1")
	for _, want := range []string{"code_challenge_method=S256", "state=state1", "client_id=Iv1.abc"} {
		if !strings.Contains(u, want) {
			t.Errorf("%s lacks %s", u, want)
		}
	}
	if strings.Contains(u, "verifier1") {
		t.Error("the verifier itself leaked into the URL")
	}
}
