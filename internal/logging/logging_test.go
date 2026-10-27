package logging

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
	"time"
)

func TestLinesAreLokiFriendlyJSON(t *testing.T) {
	var buf bytes.Buffer
	log := New(&buf, "debug")
	log.Debug("first", "pr", "rotki#1")
	log.Warn("second\nwith a newline", "status", 502)

	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("want one line per entry, got %d:\n%s", len(lines), buf.String())
	}
	for i, want := range []string{"debug", "warn"} {
		var entry map[string]any
		if err := json.Unmarshal([]byte(lines[i]), &entry); err != nil {
			t.Fatalf("line %d is not JSON: %v", i, err)
		}
		if entry["level"] != want || entry["service"] != Service || entry["message"] == nil || entry["msg"] != nil {
			t.Fatalf("line %d: %v", i, entry)
		}
		if _, err := time.Parse(time.RFC3339Nano, entry["time"].(string)); err != nil {
			t.Fatalf("time %v: %v", entry["time"], err)
		}
	}
}

func TestLevel(t *testing.T) {
	cases := map[string]slog.Level{
		"": slog.LevelInfo, "INFO": slog.LevelInfo, "Debug": slog.LevelDebug,
		"warning": slog.LevelWarn, "error": slog.LevelError, "bogus": slog.LevelInfo,
	}
	for in, want := range cases {
		if got := Level(in); got != want {
			t.Errorf("Level(%q) = %v, want %v", in, got, want)
		}
	}

	var buf bytes.Buffer
	New(&buf, "warn").Info("hidden")
	if buf.Len() != 0 {
		t.Fatalf("info logged at warn level: %s", buf.String())
	}
}
