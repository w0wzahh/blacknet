// Package blocklists downloads, validates and refreshes remote blocklists.
// Downloaded content is always treated as untrusted data: it is parsed into
// domain sets and never executed.
package blocklists

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/w0wzahh/blacknet/internal/database"
	"github.com/w0wzahh/blacknet/internal/filtering"
)

const (
	maxDownloadBytes = 64 << 20 // 64 MiB hard cap
	defaultTimeout   = 60 * time.Second
	maxRedirects     = 5
)

// ErrNotModified means the remote content hasn't changed (ETag/Last-Modified).
var ErrNotModified = errors.New("not modified")

// ErrEmpty means the downloaded body parsed to zero domains; the previous
// known-good version is kept.
var ErrEmpty = errors.New("list contained no usable domains")

// Manager owns refresh scheduling and downloads.
type Manager struct {
	db           *database.DB
	allowPrivate bool   // allow http + private-range URLs (local lists)
	onRefresh    func() // called after a successful refresh to reload the engine

	mu      sync.Mutex
	running map[int64]bool
	client  *http.Client
}

// NewManager builds a Manager. allowPrivate permits http:// URLs and
// private/loopback targets — intended for trusted local list servers; it is
// off by default for SSRF protection.
func NewManager(db *database.DB, allowPrivate bool, onRefresh func()) *Manager {
	m := &Manager{
		db:           db,
		allowPrivate: allowPrivate,
		onRefresh:    onRefresh,
		running:      map[int64]bool{},
	}
	m.client = &http.Client{
		Timeout:   defaultTimeout,
		Transport: m.transport(),
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxRedirects {
				return fmt.Errorf("too many redirects")
			}
			return m.validateURL(req.URL)
		},
	}
	return m
}

// transport dials through a connector that re-validates resolved addresses.
func (m *Manager) transport() *http.Transport {
	dialer := &net.Dialer{Timeout: 15 * time.Second}
	return &http.Transport{
		MaxIdleConns:    8,
		IdleConnTimeout: 60 * time.Second,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			if err := m.validateHost(ctx, host); err != nil {
				return nil, err
			}
			return dialer.DialContext(ctx, network, net.JoinHostPort(host, port))
		},
	}
}

// ValidateURL exposes URL checks for the API layer.
func (m *Manager) ValidateURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}
	return m.validateURL(u)
}

func (m *Manager) validateURL(u *url.URL) error {
	if u.Scheme == "https" {
		return m.validateHost(context.Background(), u.Hostname())
	}
	if u.Scheme == "http" && m.allowPrivate {
		return nil
	}
	return fmt.Errorf("only https:// sources are allowed (enable allow_private_lists for local http sources)")
}

// validateHost resolves host and rejects private/reserved ranges unless
// allowPrivate is set. DNS re-resolution is re-checked at dial time to reduce
// TOCTOU/SSRF risk.
func (m *Manager) validateHost(ctx context.Context, host string) error {
	if m.allowPrivate {
		return nil
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return checkIP(ip)
	}
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return fmt.Errorf("resolve %s: %w", host, err)
	}
	for _, ip := range ips {
		if err := checkIP(ip); err != nil {
			return err
		}
	}
	return nil
}

func checkIP(ip netip.Addr) error {
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return fmt.Errorf("address %s is not a permitted remote target", ip)
	}
	return nil
}

// RefreshResult summarises a refresh attempt.
type RefreshResult struct {
	ListID     int64    `json:"list_id"`
	Changed    bool     `json:"changed"`
	RuleCount  int      `json:"rule_count"`
	Skipped    int      `json:"skipped_lines"`
	Duplicates int      `json:"duplicates"`
	Bytes      int64    `json:"bytes"`
	Hash       string   `json:"hash"`
	Warnings   []string `json:"warnings,omitempty"`
	Message    string   `json:"message"`
}

// Refresh downloads and reparses a list atomically. A failed download or an
// empty/malformed result never replaces the last known-good data. Every
// attempt is appended to blocklist_history.
func (m *Manager) Refresh(ctx context.Context, id int64) (*RefreshResult, error) {
	m.mu.Lock()
	if m.running[id] {
		m.mu.Unlock()
		return nil, fmt.Errorf("refresh already in progress")
	}
	m.running[id] = true
	m.mu.Unlock()
	defer func() {
		m.mu.Lock()
		delete(m.running, id)
		m.mu.Unlock()
	}()

	bl, err := m.db.GetBlocklist(ctx, id)
	if err != nil {
		return nil, err
	}
	res, err := m.refreshOne(ctx, bl)
	if err != nil {
		// Record failure but keep existing rules.
		_ = m.db.UpdateBlocklistState(ctx, id, err.Error(), "", "", "", nil)
		_ = m.db.RecordBlocklistHistory(ctx, id, database.BlocklistHistoryEntry{
			Status: "failed", Error: err.Error(),
		})
		return nil, err
	}
	status := "ok"
	if !res.Changed {
		status = "unchanged"
	}
	errStr := ""
	if len(res.Warnings) > 0 {
		errStr = strings.Join(res.Warnings, "; ")
	}
	_ = m.db.RecordBlocklistHistory(ctx, id, database.BlocklistHistoryEntry{
		Status: status, RuleCount: int64(res.RuleCount), Bytes: res.Bytes,
		Malformed: int64(res.Skipped), Duplicates: int64(res.Duplicates),
		Hash: res.Hash, Error: errStr,
	})
	if m.onRefresh != nil {
		m.onRefresh()
	}
	return res, nil
}

func (m *Manager) refreshOne(ctx context.Context, bl *database.Blocklist) (*RefreshResult, error) {
	u, err := url.Parse(bl.URL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}
	if err := m.validateURL(u); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, bl.URL, nil)
	if err != nil {
		return nil, err
	}
	if bl.ETag != "" {
		req.Header.Set("If-None-Match", bl.ETag)
	}
	if bl.LastModified != "" {
		req.Header.Set("If-Modified-Since", bl.LastModified)
	}
	req.Header.Set("User-Agent", "blacknet/1.0 (+self-hosted dns filter)")

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("download: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotModified {
		return &RefreshResult{ListID: bl.ID, Changed: false, RuleCount: int(bl.RuleCount), Message: "not modified"}, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned %s", resp.Status)
	}
	if cl := resp.ContentLength; cl > maxDownloadBytes {
		return nil, fmt.Errorf("list too large (%d bytes)", cl)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxDownloadBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}
	if len(body) > maxDownloadBytes {
		return nil, fmt.Errorf("list exceeds %d byte limit", maxDownloadBytes)
	}

	sum := sha256.Sum256(body)
	hash := hex.EncodeToString(sum[:])
	if hash == bl.ContentHash && bl.RuleCount > 0 {
		return &RefreshResult{ListID: bl.ID, Changed: false, RuleCount: int(bl.RuleCount), Message: "content unchanged"}, nil
	}

	parsed := filtering.ParseList(strings.NewReader(string(body)))
	if len(parsed.Blocks) == 0 {
		return nil, ErrEmpty
	}
	// Quality warnings — surfaced in history and the API, never fatal.
	var warnings []string
	if parsed.Total > 0 && parsed.Skipped > parsed.Total/4 {
		warnings = append(warnings,
			fmt.Sprintf("%d/%d lines could not be parsed — check this is a domain list", parsed.Skipped, parsed.Total))
	}
	if bl.RuleCount > 0 {
		newCount := int64(len(parsed.Blocks))
		if newCount < bl.RuleCount/2 {
			warnings = append(warnings,
				fmt.Sprintf("rule count dropped sharply: %d → %d", bl.RuleCount, newCount))
		} else if newCount > bl.RuleCount*3 {
			warnings = append(warnings,
				fmt.Sprintf("rule count grew sharply: %d → %d", bl.RuleCount, newCount))
		}
	}
	if parsed.Duplicates > len(parsed.Blocks)/2 {
		warnings = append(warnings,
			fmt.Sprintf("%d duplicate entries — list quality is low", parsed.Duplicates))
	}
	domains := &database.BlocklistDomains{Blocks: parsed.Blocks, Allows: parsed.Allows}
	etag := resp.Header.Get("ETag")
	lm := resp.Header.Get("Last-Modified")
	if err := m.db.UpdateBlocklistState(ctx, bl.ID, "", etag, lm, hash, domains); err != nil {
		return nil, err
	}
	return &RefreshResult{
		ListID: bl.ID, Changed: true,
		RuleCount: len(parsed.Blocks), Skipped: parsed.Skipped,
		Duplicates: parsed.Duplicates, Bytes: int64(len(body)), Hash: hash,
		Warnings: warnings,
		Message:  fmt.Sprintf("imported %d domains", len(parsed.Blocks)),
	}, nil
}

// RefreshAll refreshes every enabled list that is due (older than interval or
// never refreshed).
func (m *Manager) RefreshAll(ctx context.Context, interval time.Duration) []RefreshResult {
	lists, err := m.db.ListBlocklists(ctx)
	if err != nil {
		return nil
	}
	var out []RefreshResult
	for _, bl := range lists {
		if !bl.Enabled {
			continue
		}
		due := bl.LastRefresh == ""
		if !due {
			if t, err := time.Parse(time.RFC3339, bl.LastRefresh); err == nil {
				due = time.Since(t) >= interval
			} else {
				due = true
			}
		}
		if !due {
			continue
		}
		res, err := m.Refresh(ctx, bl.ID)
		if err != nil {
			out = append(out, RefreshResult{ListID: bl.ID, Message: err.Error()})
			continue
		}
		out = append(out, *res)
	}
	return out
}
