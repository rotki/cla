// Package logging builds the JSON logger, shaped like the other rotki
// services so Loki and Grafana treat them alike: one JSON object per line on
// stdout, a lower-case "level" (which Loki detects), an RFC 3339 "time", the
// text under "message", and a "service" field to filter on.
package logging

import (
	"io"
	"log/slog"
	"strings"
	"time"
)

// Service is the value of the "service" field.
const Service = "cla"

// New returns a logger writing to w at the level LOG_LEVEL names (debug,
// info, warn, error; info when empty or unknown).
func New(w io.Writer, level string) *slog.Logger {
	handler := slog.NewJSONHandler(w, &slog.HandlerOptions{
		Level:       Level(level),
		ReplaceAttr: replace,
	})
	return slog.New(handler).With("service", Service)
}

// Level parses a LOG_LEVEL value.
func Level(value string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	}
	return slog.LevelInfo
}

func replace(groups []string, a slog.Attr) slog.Attr {
	if len(groups) > 0 {
		return a
	}
	switch a.Key {
	case slog.LevelKey:
		if l, ok := a.Value.Any().(slog.Level); ok {
			return slog.String(slog.LevelKey, strings.ToLower(l.String()))
		}
	case slog.MessageKey:
		a.Key = "message"
	case slog.TimeKey:
		if t, ok := a.Value.Any().(time.Time); ok {
			return slog.String(slog.TimeKey, t.UTC().Format(time.RFC3339Nano))
		}
	}
	return a
}
