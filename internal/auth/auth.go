// Package auth implements dashboard authentication: argon2id password
// hashing, in-memory sessions, a static API token for the CLI, and login
// rate limiting.
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
)

const (
	sessionTTL   = 12 * time.Hour
	argonTime    = 3
	argonMemory  = 64 * 1024
	argonThreads = 2
	argonKeyLen  = 32
	saltLen      = 16
)

// Manager tracks password hash, sessions and login throttling.
type Manager struct {
	mu       sync.Mutex
	hash     string // argon2id encoded string; empty = not set
	sessions map[string]time.Time
	apiToken string

	// login rate limiting: ip -> attempts window
	attempts map[string][]time.Time
}

func New(apiToken string) *Manager {
	return &Manager{apiToken: apiToken, sessions: map[string]time.Time{}, attempts: map[string][]time.Time{}}
}

// HasPassword reports whether an admin password has been configured.
func (m *Manager) HasPassword() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.hash != ""
}

// SetPassword stores a new argon2id hash.
func (m *Manager) SetPassword(password string) error {
	if len(password) < 8 {
		return errors.New("password must be at least 8 characters")
	}
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	key := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	enc := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key))
	m.mu.Lock()
	m.hash = enc
	m.sessions = map[string]time.Time{} // invalidate existing sessions
	m.mu.Unlock()
	return nil
}

// LoadHash restores a persisted hash.
func (m *Manager) LoadHash(h string) { m.mu.Lock(); m.hash = h; m.mu.Unlock() }
func (m *Manager) Hash() string      { m.mu.Lock(); defer m.mu.Unlock(); return m.hash }

// CheckPassword verifies a password against the stored hash.
func (m *Manager) CheckPassword(password string) bool {
	m.mu.Lock()
	h := m.hash
	m.mu.Unlock()
	if h == "" {
		return false
	}
	parts := strings.Split(h, "$")
	if len(parts) != 6 {
		return false
	}
	var mem uint32
	var t, p uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &mem, &t, &p); err != nil {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false
	}
	got := argon2.IDKey([]byte(password), salt, uint32(t), mem, p, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}

// CreateSession returns a new session token.
func (m *Manager) CreateSession() string {
	buf := make([]byte, 32)
	rand.Read(buf)
	tok := base64.RawURLEncoding.EncodeToString(buf)
	m.mu.Lock()
	m.sessions[tok] = time.Now().Add(sessionTTL)
	m.mu.Unlock()
	return tok
}

// ValidSession checks and refreshes a session token.
func (m *Manager) ValidSession(tok string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	exp, ok := m.sessions[tok]
	if !ok || time.Now().After(exp) {
		delete(m.sessions, tok)
		return false
	}
	m.sessions[tok] = time.Now().Add(sessionTTL)
	return true
}

// DestroySession removes a token.
func (m *Manager) DestroySession(tok string) {
	m.mu.Lock()
	delete(m.sessions, tok)
	m.mu.Unlock()
}

// CheckAPIToken compares a bearer token with the static API token.
func (m *Manager) CheckAPIToken(tok string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.apiToken == "" || tok == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(tok), []byte(m.apiToken)) == 1
}

// AllowLogin implements a simple per-IP rate limit: max 8 attempts / minute.
func (m *Manager) AllowLogin(ip string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	cutoff := now.Add(-time.Minute)
	kept := m.attempts[ip][:0]
	for _, t := range m.attempts[ip] {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	if len(kept) >= 8 {
		m.attempts[ip] = kept
		return false
	}
	m.attempts[ip] = append(kept, now)
	return true
}

// TokenFromRequest extracts a session cookie or bearer token.
func TokenFromRequest(r *http.Request) (string, bool) {
	if c, err := r.Cookie("blacknet_session"); err == nil && c.Value != "" {
		return c.Value, true
	}
	h := r.Header.Get("Authorization")
	if strings.HasPrefix(h, "Bearer ") {
		return strings.TrimPrefix(h, "Bearer "), true
	}
	return "", false
}
