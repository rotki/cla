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
		switch r.URL.Path {
		case "/meta":
			_, _ = w.Write([]byte(`{"hooks":["192.30.252.0/22","2a0a:a440::/29","bogus"]}`))
		case "/grown/meta":
			_, _ = w.Write([]byte(`{"hooks":["192.30.252.0/22","2a0a:a440::/29","198.51.100.0/24"]}`))
		default:
			http.NotFound(w, r)
		}
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
		// An address that does not parse cannot be ruled out.
		{"not an address", peer, true},
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

	// A valid delivery from outside, as behind a CDN, makes them blind
	// and asks for a refresh.
	s.sawValid(request("192.30.252.17", peer))
	if s.fromGitHub(request("203.0.113.9", peer)) {
		t.Fatal("a valid delivery from inside made the ranges blind")
	}
	s.sawValid(request("198.51.100.4", peer))
	if !s.fromGitHub(request("203.0.113.9", peer)) || len(s.stale) != 1 {
		t.Fatalf("a valid delivery from outside: blind %v, refresh asked %d", len(s.outside) > 0, len(s.stale))
	}
	// The same address again asks for nothing more.
	<-s.stale
	s.sawValid(request("198.51.100.4", peer))
	if len(s.stale) != 0 {
		t.Fatal("a known outside address asked for another refresh")
	}
	// A refresh that still leaves the address out proves nothing: behind a
	// CDN no later one will cover it either, and with a broken secret no
	// valid delivery would come to make the ranges blind again.
	if err := s.Refresh(context.Background(), githubapp.NewPublicClient(meta.URL)); err != nil || !s.fromGitHub(request("198.51.100.4", peer)) {
		t.Fatalf("a refresh that does not cover the address cleared blindness: %v", err)
	}
	// One that covers it, as when GitHub added the range, clears it.
	if err := s.Refresh(context.Background(), githubapp.NewPublicClient(meta.URL+"/grown")); err != nil || s.fromGitHub(request("203.0.113.9", peer)) {
		t.Fatalf("a refresh that covers the address did not clear blindness: %v", err)
	}

	var none *Sources
	if !none.fromGitHub(request("203.0.113.9", peer)) {
		t.Fatal("without sources every request must count as GitHub's")
	}
	none.markStale()
	none.sawValid(request("203.0.113.9", peer))
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

func TestEarlyRefreshTooSoonIsPutOff(t *testing.T) {
	var calls atomic.Int32
	meta := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		_, _ = w.Write([]byte(`{"hooks":["192.30.252.0/22"]}`))
	}))
	defer meta.Close()

	s := NewSources()
	s.minAge = 200 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx, githubapp.NewPublicClient(meta.URL), time.Hour)
	for calls.Load() == 0 {
		time.Sleep(10 * time.Millisecond)
	}

	// Asked for at once, the refresh waits out minAge, then happens.
	s.markStale()
	time.Sleep(50 * time.Millisecond)
	if n := calls.Load(); n != 1 {
		t.Fatalf("refreshed %d times before minAge", n)
	}
	for deadline := time.Now().Add(5 * time.Second); calls.Load() < 2; {
		if time.Now().After(deadline) {
			t.Fatal("the early refresh asked for too soon never happened")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
