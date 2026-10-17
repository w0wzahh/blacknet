// Package cache provides a bounded, TTL-aware in-memory DNS response cache.
package cache

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

type key struct {
	name  string
	qtype uint16
}

type entry struct {
	msg       *dns.Msg // deep copy; Id is normalized to 0
	expiresAt time.Time
	negative  bool
}

// Stats is a point-in-time snapshot of cache counters.
type Stats struct {
	Entries   int64 `json:"entries"`
	Hits      int64 `json:"hits"`
	Misses    int64 `json:"misses"`
	Evictions int64 `json:"evictions"`
	Inserts   int64 `json:"inserts"`
	MaxSize   int   `json:"max_size"`
}

// Cache stores successful and negative DNS answers keyed by (name, qtype).
// Safe for concurrent use.
type Cache struct {
	mu         sync.Mutex
	items      map[key]*entry
	maxEntries int
	minTTL     time.Duration
	maxTTL     time.Duration
	negTTL     time.Duration
	enabled    atomic.Bool

	hits      atomic.Int64
	misses    atomic.Int64
	evictions atomic.Int64
	inserts   atomic.Int64
}

// New creates a cache. minTTL/maxTTL bound positive answer TTLs; negTTL is the
// fallback lifetime for NXDOMAIN/NODATA responses that carry no SOA.
func New(maxEntries int, minTTL, maxTTL, negTTL time.Duration) *Cache {
	if maxEntries <= 0 {
		maxEntries = 10000
	}
	c := &Cache{
		items:      make(map[key]*entry, maxEntries),
		maxEntries: maxEntries,
		minTTL:     minTTL,
		maxTTL:     maxTTL,
		negTTL:     negTTL,
	}
	c.enabled.Store(true)
	return c
}

func (c *Cache) SetEnabled(on bool) { c.enabled.Store(on) }
func (c *Cache) Enabled() bool      { return c.enabled.Load() }

// Get returns a copy of a cached response for the question, or nil on miss.
// The caller must set the returned message's Id to the request Id. Answer TTLs
// are rewritten to the remaining lifetime.
func (c *Cache) Get(name string, qtype uint16) *dns.Msg {
	if !c.enabled.Load() {
		return nil
	}
	k := key{name: name, qtype: qtype}
	now := time.Now()
	c.mu.Lock()
	e, ok := c.items[k]
	if !ok {
		c.mu.Unlock()
		c.misses.Add(1)
		return nil
	}
	if now.After(e.expiresAt) {
		delete(c.items, k)
		c.mu.Unlock()
		c.misses.Add(1)
		return nil
	}
	msg := e.msg.Copy()
	neg := e.negative
	remaining := time.Until(e.expiresAt)
	c.mu.Unlock()

	c.hits.Add(1)
	msg.Id = 0
	if !neg {
		ttl := uint32(remaining / time.Second)
		for _, rr := range msg.Answer {
			rr.Header().Ttl = ttl
		}
		for _, rr := range msg.Ns {
			rr.Header().Ttl = ttl
		}
		for _, rr := range msg.Extra {
			if rr.Header().Rrtype != dns.TypeOPT {
				rr.Header().Ttl = ttl
			}
		}
	}
	return msg
}

// Store inserts resp into the cache. Transient failures (SERVFAIL, REFUSED,
// FORMERR, ...) are never cached. Positive answers live for the smallest RR
// TTL clamped to [minTTL, maxTTL]; NXDOMAIN/NODATA live for the SOA TTL if
// present, else negTTL, capped at maxTTL.
func (c *Cache) Store(req *dns.Msg, resp *dns.Msg) {
	if !c.enabled.Load() || req == nil || resp == nil || len(req.Question) == 0 {
		return
	}
	var ttl time.Duration
	negative := false
	switch resp.Rcode {
	case dns.RcodeSuccess:
		if len(resp.Answer) > 0 {
			ttl = c.positiveTTL(resp)
		} else {
			negative = true
			ttl = c.negativeTTL(resp)
		}
	case dns.RcodeNameError: // NXDOMAIN
		negative = true
		ttl = c.negativeTTL(resp)
	default:
		return // never cache transient failures
	}
	if ttl <= 0 {
		return
	}
	q := req.Question[0]
	k := key{name: NormalizeName(q.Name), qtype: q.Qtype}

	m := resp.Copy()
	m.Id = 0

	c.mu.Lock()
	if len(c.items) >= c.maxEntries {
		c.evictLocked()
	}
	c.items[k] = &entry{msg: m, expiresAt: time.Now().Add(ttl), negative: negative}
	c.mu.Unlock()
	c.inserts.Add(1)
}

func (c *Cache) positiveTTL(m *dns.Msg) time.Duration {
	var min uint32 = 1<<31 - 1
	for _, rr := range m.Answer {
		if rr.Header().Ttl < min {
			min = rr.Header().Ttl
		}
	}
	d := time.Duration(min) * time.Second
	if d < c.minTTL {
		d = c.minTTL
	}
	if c.maxTTL > 0 && d > c.maxTTL {
		d = c.maxTTL
	}
	return d
}

func (c *Cache) negativeTTL(m *dns.Msg) time.Duration {
	d := c.negTTL
	for _, rr := range m.Ns {
		if soa, ok := rr.(*dns.SOA); ok {
			soaTTL := soa.Header().Ttl
			if soa.Minttl < soaTTL {
				soaTTL = soa.Minttl
			}
			if soaTTL > 0 {
				d = time.Duration(soaTTL) * time.Second
			}
			break
		}
	}
	if c.maxTTL > 0 && d > c.maxTTL {
		d = c.maxTTL
	}
	return d
}

// evictLocked drops expired entries; if still over capacity it removes ~10%
// of the oldest entries. Must be called with c.mu held.
func (c *Cache) evictLocked() {
	now := time.Now()
	for k, e := range c.items {
		if now.After(e.expiresAt) {
			delete(c.items, k)
			c.evictions.Add(1)
		}
	}
	if len(c.items) < c.maxEntries {
		return
	}
	target := c.maxEntries - c.maxEntries/10
	for k := range c.items {
		if len(c.items) <= target {
			break
		}
		delete(c.items, k)
		c.evictions.Add(1)
	}
}

// Flush removes all entries.
func (c *Cache) Flush() {
	c.mu.Lock()
	c.items = make(map[key]*entry, c.maxEntries)
	c.mu.Unlock()
}

// Stats returns a snapshot of counters.
func (c *Cache) Stats() Stats {
	c.mu.Lock()
	n := len(c.items)
	c.mu.Unlock()
	return Stats{
		Entries:   int64(n),
		Hits:      c.hits.Load(),
		Misses:    c.misses.Load(),
		Evictions: c.evictions.Load(),
		Inserts:   c.inserts.Load(),
		MaxSize:   c.maxEntries,
	}
}

// NormalizeName lowercases an fqdn and strips the trailing dot.
func NormalizeName(s string) string {
	if len(s) > 0 && s[len(s)-1] == '.' {
		s = s[:len(s)-1]
	}
	out := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if ch >= 'A' && ch <= 'Z' {
			ch += 'a' - 'A'
		}
		out[i] = ch
	}
	return string(out)
}
