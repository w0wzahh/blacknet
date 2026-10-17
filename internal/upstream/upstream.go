// Package upstream manages configurable upstream DNS resolvers
// (UDP, TCP, DoT and DoH), failover, health checks and statistics.
package upstream

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

// Protocol selects the transport used to reach an upstream resolver.
type Protocol string

const (
	ProtoUDP Protocol = "udp"
	ProtoTCP Protocol = "tcp"
	ProtoDoT Protocol = "dot"
	ProtoDoH Protocol = "doh"
)

// Config describes a single upstream resolver.
type Config struct {
	ID       int64         `json:"id"`
	Name     string        `json:"name"`
	Protocol Protocol      `json:"protocol"`
	Address  string        `json:"address"` // host:port, or https:// URL for DoH
	Priority int           `json:"priority"`
	Timeout  time.Duration `json:"timeout"`
	Enabled  bool          `json:"enabled"`
}

// Validate checks a Config for correctness.
func (c *Config) Validate() error {
	switch c.Protocol {
	case ProtoUDP, ProtoTCP, ProtoDoT:
		host, port, err := net.SplitHostPort(c.Address)
		if err != nil || host == "" || port == "" {
			return fmt.Errorf("address must be host:port, got %q", c.Address)
		}
	case ProtoDoH:
		if !strings.HasPrefix(c.Address, "https://") {
			// Allow plain http only for loopback test endpoints.
			rest := strings.TrimPrefix(c.Address, "http://")
			if rest == c.Address {
				return fmt.Errorf("DoH address must be an https:// URL")
			}
			host := rest
			if i := strings.IndexAny(host, "/:"); i >= 0 {
				host = host[:i]
			}
			if ip, err := netip.ParseAddr(host); err != nil || !ip.IsLoopback() {
				if host != "localhost" {
					return fmt.Errorf("DoH address must use https:// (http allowed only for loopback)")
				}
			}
		}
	default:
		return fmt.Errorf("unknown protocol %q", c.Protocol)
	}
	if c.Timeout <= 0 {
		c.Timeout = 5 * time.Second
	}
	if c.Timeout > 30*time.Second {
		return fmt.Errorf("timeout too large")
	}
	return nil
}

// Stats describes a resolver's observed behaviour.
type Stats struct {
	LastRTTms  float64 `json:"last_rtt_ms"`
	LastError  string  `json:"last_error,omitempty"`
	LastCheck  string  `json:"last_check,omitempty"`
	Healthy    bool    `json:"healthy"`
	Queries    int64   `json:"queries"`
	Failures   int64   `json:"failures"`
	CheckedAts int64   `json:"-"`
}

type resolver struct {
	cfg   Config
	dns   *dns.Client
	http  *http.Client
	stats struct {
		queries  atomic.Int64
		failures atomic.Int64
	}
	mu        sync.Mutex
	lastRTT   time.Duration
	lastErr   string
	lastCheck time.Time
	healthy   bool
}

func newResolver(c Config) (*resolver, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	r := &resolver{cfg: c}
	switch c.Protocol {
	case ProtoUDP:
		r.dns = &dns.Client{Net: "udp", Timeout: c.Timeout}
	case ProtoTCP:
		r.dns = &dns.Client{Net: "tcp", Timeout: c.Timeout}
	case ProtoDoT:
		host, _, err := net.SplitHostPort(c.Address)
		if err != nil {
			return nil, err
		}
		r.dns = &dns.Client{
			Net:       "tcp-tls",
			Timeout:   c.Timeout,
			TLSConfig: &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12},
		}
	case ProtoDoH:
		r.http = &http.Client{
			Timeout: c.Timeout + 2*time.Second,
			Transport: &http.Transport{
				MaxIdleConns:       8,
				IdleConnTimeout:    90 * time.Second,
				TLSClientConfig:    &tls.Config{MinVersion: tls.VersionTLS12},
				ForceAttemptHTTP2:  true,
				DisableCompression: true,
			},
		}
	}
	return r, nil
}

// exchange sends req through this resolver.
func (r *resolver) exchange(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	r.stats.queries.Add(1)
	start := time.Now()
	var resp *dns.Msg
	var err error
	switch r.cfg.Protocol {
	case ProtoUDP, ProtoTCP, ProtoDoT:
		resp, _, err = r.dns.ExchangeContext(ctx, req, r.cfg.Address)
	case ProtoDoH:
		resp, err = r.exchangeDoH(ctx, req)
	default:
		err = fmt.Errorf("unsupported protocol %q", r.cfg.Protocol)
	}
	rtt := time.Since(start)
	r.mu.Lock()
	r.lastRTT = rtt
	if err != nil {
		r.lastErr = err.Error()
		r.healthy = false
		r.stats.failures.Add(1)
	} else {
		r.lastErr = ""
		r.healthy = true
	}
	r.lastCheck = time.Now()
	r.mu.Unlock()
	return resp, err
}

func (r *resolver) exchangeDoH(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	raw, err := req.Pack()
	if err != nil {
		return nil, err
	}
	hreq, err := http.NewRequestWithContext(ctx, http.MethodPost, r.cfg.Address, bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	hreq.Header.Set("Content-Type", "application/dns-message")
	hreq.Header.Set("Accept", "application/dns-message")
	hresp, err := r.http.Do(hreq)
	if err != nil {
		return nil, err
	}
	defer hresp.Body.Close()
	if hresp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH server returned %s", hresp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(hresp.Body, 64*1024))
	if err != nil {
		return nil, err
	}
	resp := new(dns.Msg)
	if err := resp.Unpack(body); err != nil {
		return nil, fmt.Errorf("invalid DoH response: %w", err)
	}
	return resp, nil
}

func (r *resolver) snapshot() Stats {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := Stats{
		LastRTTms: float64(r.lastRTT) / float64(time.Millisecond),
		LastError: r.lastErr,
		Healthy:   r.healthy,
		Queries:   r.stats.queries.Load(),
		Failures:  r.stats.failures.Load(),
	}
	if !r.lastCheck.IsZero() {
		s.LastCheck = r.lastCheck.UTC().Format(time.RFC3339)
	}
	return s
}

// Pool resolves queries through an ordered set of upstream resolvers.
type Pool struct {
	mu        sync.RWMutex
	resolvers []*resolver // sorted by Priority ascending
	parallel  bool
	failOpen  atomic.Bool
}

// NewPool builds a pool from the given configs; invalid configs are skipped
// with an error return so callers can surface configuration problems.
func NewPool(cfgs []Config, parallel bool) (*Pool, error) {
	p := &Pool{parallel: parallel}
	return p, p.SetResolvers(cfgs, parallel)
}

// SetResolvers atomically replaces the pool's resolver set.
func (p *Pool) SetResolvers(cfgs []Config, parallel bool) error {
	var rs []*resolver
	var firstErr error
	for _, c := range cfgs {
		if !c.Enabled {
			continue
		}
		r, err := newResolver(c)
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("upstream %q: %w", c.Name, err)
			}
			continue
		}
		rs = append(rs, r)
	}
	sortByPriority(rs)
	p.mu.Lock()
	p.resolvers = rs
	p.parallel = parallel
	p.mu.Unlock()
	return firstErr
}

func sortByPriority(rs []*resolver) {
	for i := 1; i < len(rs); i++ {
		for j := i; j > 0 && rs[j].cfg.Priority < rs[j-1].cfg.Priority; j-- {
			rs[j], rs[j-1] = rs[j-1], rs[j]
		}
	}
}

// SetFailOpen controls whether SERVFAIL responses are suppressed; kept for API
// completeness, the DNS server owns the actual policy.
func (p *Pool) SetFailOpen(v bool) { p.failOpen.Store(v) }

// Exchange forwards req to upstream resolvers. In sequential mode it tries
// resolvers in priority order, failing over on transport errors; a received
// response (even SERVFAIL) is returned immediately. In parallel mode the
// first successful transport wins. Returns an error only when every resolver
// fails.
func (p *Pool) Exchange(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	p.mu.RLock()
	rs := make([]*resolver, len(p.resolvers))
	copy(rs, p.resolvers)
	parallel := p.parallel
	p.mu.RUnlock()

	if len(rs) == 0 {
		return nil, errors.New("no upstream resolvers configured")
	}
	if parallel && len(rs) > 1 {
		return p.exchangeParallel(ctx, rs, req)
	}
	var lastErr error
	for _, r := range rs {
		resp, err := r.exchange(ctx, req)
		if err == nil {
			return resp, nil
		}
		lastErr = err
	}
	return nil, fmt.Errorf("all upstreams failed: %w", lastErr)
}

func (p *Pool) exchangeParallel(ctx context.Context, rs []*resolver, req *dns.Msg) (*dns.Msg, error) {
	type result struct {
		msg *dns.Msg
		err error
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ch := make(chan result, len(rs))
	for _, r := range rs {
		go func(r *resolver) {
			q := req.Copy()
			m, err := r.exchange(ctx, q)
			select {
			case ch <- result{m, err}:
			case <-ctx.Done():
			}
		}(r)
	}
	var lastErr error
	for range rs {
		res := <-ch
		if res.err == nil {
			return res.msg, nil
		}
		lastErr = res.err
	}
	return nil, fmt.Errorf("all upstreams failed: %w", lastErr)
}

// ExchangeWith forwards through exactly one resolver (a policy group's
// upstream override). Returns an error when the id is unknown or disabled.
func (p *Pool) ExchangeWith(ctx context.Context, id int64, req *dns.Msg) (*dns.Msg, error) {
	p.mu.RLock()
	var target *resolver
	for _, r := range p.resolvers {
		if r.cfg.ID == id {
			target = r
			break
		}
	}
	p.mu.RUnlock()
	if target == nil {
		return nil, fmt.Errorf("upstream %d not available", id)
	}
	return target.exchange(ctx, req)
}

// ResolverByID returns a Resolver bound to one upstream, or nil.
// Used to serve group-scoped upstream overrides without locking the pool.
func (p *Pool) ResolverByID(id int64) func(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	return func(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
		return p.ExchangeWith(ctx, id, req)
	}
}

// Stats returns a snapshot for every configured resolver (enabled or not).
func (p *Pool) Stats() map[int64]Stats {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make(map[int64]Stats, len(p.resolvers))
	for _, r := range p.resolvers {
		out[r.cfg.ID] = r.snapshot()
	}
	return out
}

// Test performs a real resolution against every configured resolver and
// returns per-resolver results keyed by config ID.
func (p *Pool) Test(ctx context.Context, probe string) map[int64]Stats {
	p.mu.RLock()
	rs := make([]*resolver, len(p.resolvers))
	copy(rs, p.resolvers)
	p.mu.RUnlock()
	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(probe), dns.TypeA)
	q.RecursionDesired = true
	for _, r := range rs {
		cctx, cancel := context.WithTimeout(ctx, r.cfg.Timeout+time.Second)
		_, _ = r.exchange(cctx, q)
		cancel()
	}
	return p.Stats()
}

// Healthy reports whether at least one resolver currently works.
func (p *Pool) Healthy() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	for _, r := range p.resolvers {
		r.mu.Lock()
		ok := r.healthy
		r.mu.Unlock()
		if ok {
			return true
		}
	}
	return len(p.resolvers) == 0 // unconfigured = not yet evaluated
}
