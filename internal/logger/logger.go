// Package logger provides leveled, component-scoped logging for the pwn project.
//
// Output format:
//
//	INFO  →  2026/03/30 21:04:38 [proxy] SOCKS5 listening on :1080
//	DEBUG →  2026/03/30 21:04:38 DBG [proxy] new conn src=127.0.0.1:54321
//	WARN  →  2026/03/30 21:04:38 WRN [proxy] auth failed user="bob"
//	ERROR →  2026/03/30 21:04:38 ERR [proxy] SendData: broken pipe
//
// Debug output is suppressed by default; call SetDebug(true) to enable it.
// Info output matches the existing [component] style used throughout the project.
package logger

import (
	"log"
	"sync/atomic"
)

var debugEnabled atomic.Bool

// SetDebug enables or disables debug-level output globally.
func SetDebug(on bool) { debugEnabled.Store(on) }

// IsDebug reports whether debug logging is currently enabled.
func IsDebug() bool { return debugEnabled.Load() }

// Logger is a component-scoped logger.  All output lines are prefixed with
// [tag] so log lines are easy to filter by component.
type Logger struct {
	tag string // component name, e.g. "proxy", "relay"
}

// New returns a Logger that prefixes every line with [tag].
func New(tag string) *Logger { return &Logger{tag: tag} }

// Debug emits a debug line.  It is a no-op when debug logging is disabled.
func (l *Logger) Debug(format string, args ...any) {
	if debugEnabled.Load() {
		log.Printf("DBG ["+l.tag+"] "+format, args...)
	}
}

// Info emits an info line.  Always shown; format matches the existing project
// style so callers do not need to include the [tag] themselves.
func (l *Logger) Info(format string, args ...any) {
	log.Printf("["+l.tag+"] "+format, args...)
}

// Warn emits a warning line.  Always shown.
func (l *Logger) Warn(format string, args ...any) {
	log.Printf("WRN ["+l.tag+"] "+format, args...)
}

// Error emits an error line.  Always shown.
func (l *Logger) Error(format string, args ...any) {
	log.Printf("ERR ["+l.tag+"] "+format, args...)
}

// Fatal emits an error line then calls os.Exit(1) via log.Fatalf.
func (l *Logger) Fatal(format string, args ...any) {
	log.Fatalf("ERR ["+l.tag+"] "+format, args...)
}
