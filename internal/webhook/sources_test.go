package webhook

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rotki/cla/internal/githubapp"
)

func request(realIP, peer string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/webhook", http.NoBody)
	r.RemoteAddr = peer
	if realIP != "" {
		r.Header.Set("X-Real-Ip", realIP)
	}
	return r
}

func TestSourcesTellGitHubFromOthers(t *testing.T) {
	meta := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/meta" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`{"hooks":["192.30.252.0/22","2a0a:a440::/29","bogus"]}`))
	}))
	defer meta.Close()

	s := NewSources()
	peer := "10.0.0.2:4711"
	if !s.fromGitHub(request("203.0.113.9", peer)) {
		t.Fatal("before the ranges are loaded every request must count as GitHub's")
	}
	if err := s.Refresh(context.Background(), githubapp.NewPublicClient(meta.URL)); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		realIP, peer string
		want         bool
	}{
		{"192.30.252.17", peer, true},
		{"2a0a:a440::1", peer, true},
		{"::ffff:192.30.253.1", peer, true},
		{"203.0.113.9", peer, false},
		{"not an address", peer, false},
		{"", "192.30.254.3:443", true},
		{"", "203.0.113.9:443", false},
	}
	for _, tc := range cases {
		if got := s.fromGitHub(request(tc.realIP, tc.peer)); got != tc.want {
			t.Errorf("X-Real-Ip %q, peer %q: fromGitHub = %v, want %v", tc.realIP, tc.peer, got, tc.want)
		}
	}

	// A failed refresh keeps what was loaded.
	if err := s.Refresh(context.Background(), githubapp.NewPublicClient(meta.URL+"/gone")); err == nil {
		t.Fatal("a missing /meta did not fail")
	}
	if !s.fromGitHub(request("192.30.252.17", peer)) || s.fromGitHub(request("203.0.113.9", peer)) {
		t.Fatal("a failed refresh dropped the ranges")
	}

	var none *Sources
	if !none.fromGitHub(request("203.0.113.9", peer)) {
		t.Fatal("without sources every request must count as GitHub's")
	}
	none.markStale()
}

func TestEarlyRefreshesAreThrottled(t *testing.T) {
	var calls atomic.Int32
	meta := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		_, _ = w.Write([]byte(`{"hooks":["192.30.252.0/22"]}`))
	}))
	defer meta.Close()

	s := NewSources()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.Run(ctx, githubapp.NewPublicClient(meta.URL), time.Hour); close(done) }()
	for deadline := time.Now().Add(5 * time.Second); calls.Load() == 0; {
		if time.Now().After(deadline) {
			t.Fatal("the ranges were never loaded")
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Junk from elsewhere right after a refresh must not reach /meta again.
	for range 100 {
		s.markStale()
	}
	time.Sleep(100 * time.Millisecond)
	cancel()
	<-done
	if n := calls.Load(); n != 1 {
		t.Fatalf("/meta called %d times", n)
	}
}
