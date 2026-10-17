// Package logging configures Go structured logging for Blacknet.
package logging

import (
	"log/slog"
	"os"
	"strings"
)

// Init sets the default slog logger according to level ("debug", "info",
// "warn", "error"). Output is human-readable text on stderr.
func Init(level string) {
	var lv slog.Level
	switch strings.ToLower(level) {
	case "debug":
		lv = slog.LevelDebug
	case "warn":
		lv = slog.LevelWarn
	case "error":
		lv = slog.LevelError
	default:
		lv = slog.LevelInfo
	}
	h := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lv})
	slog.SetDefault(slog.New(h))
}
