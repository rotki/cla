package web

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// requestLog collects the paths the access log writes a line for.
type requestLog struct {
	mu    sync.Mutex
	paths []string
}

func (l *requestLog) Enabled(context.Context, slog.Level) bool { return true }
func (l *requestLog) WithAttrs([]slog.Attr) slog.Handler       { return l }
func (l *requestLog) WithGroup(string) slog.Handler            { return l }

func (l *requestLog) Handle(_ context.Context, r slog.Record) error {
	if r.Message != "request" {
		return nil
	}
	r.Attrs(func(a slog.Attr) bool {
		if a.Key == "path" {
			l.mu.Lock()
			l.paths = append(l.paths, a.Value.String())
			l.mu.Unlock()
		}
		return true
	})
	return nil
}

func TestAccessLogSkipsDirectProbes(t *testing.T) {
	logs := &requestLog{}
	prev := slog.Default()
	slog.SetDefault(slog.New(logs))
	t.Cleanup(func() { slog.SetDefault(prev) })

	status := http.StatusOK
	h := accessLog(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
	}))
	for _, tc := range []struct {
		path   string
		realIP string
		status int
		logged bool
	}{
		{healthPath, "", http.StatusOK, false},
		{readyPath, "", http.StatusOK, false},
		{readyPath, "", http.StatusServiceUnavailable, true},
		{healthPath, "203.0.113.7", http.StatusOK, true},
		{"/cla", "", http.StatusOK, true},
	} {
		logs.mu.Lock()
		logs.paths = nil
		logs.mu.Unlock()
		status = tc.status
		r := httptest.NewRequest(http.MethodGet, tc.path, nil)
		r.RemoteAddr = "10.0.1.31:41234"
		if tc.realIP != "" {
			r.Header.Set("X-Real-Ip", tc.realIP)
		}
		h.ServeHTTP(httptest.NewRecorder(), r)
		logs.mu.Lock()
		got := len(logs.paths) == 1
		logs.mu.Unlock()
		if got != tc.logged {
			t.Errorf("%s (X-Real-Ip %q, status %d): logged = %v, want %v", tc.path, tc.realIP, tc.status, got, tc.logged)
		}
	}
}
