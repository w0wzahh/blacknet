package database

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/w0wzahh/blacknet/internal/dnsserver"
)

// QueryRow is one stored query-log entry.
type QueryRow struct {
	ID        int64   `json:"id"`
	Time      string  `json:"time"`
	ClientIP  string  `json:"client_ip"`
	ClientID  int64   `json:"client_id"`
	Alias     string  `json:"alias,omitempty"`
	Domain    string  `json:"domain"`
	QType     uint16  `json:"qtype"`
	QTypeName string  `json:"qtype_name"`
	Blocked   bool    `json:"blocked"`
	Reason    string  `json:"reason"`
	RCode     int     `json:"rcode"`
	RCodeName string  `json:"rcode_name"`
	LatencyMs float64 `json:"latency_ms"`
	Cached    bool    `json:"cached"`
}

// QueryFilter selects rows in ListQueries.
type QueryFilter struct {
	Domain   string // substring match
	ClientIP string // exact
	Blocked  *bool
	QType    *uint16
	Since    time.Time
	Until    time.Time
	Limit    int
	Offset   int
}

// ListQueries returns matching rows plus the total count for pagination.
func (db *DB) ListQueries(ctx context.Context, f QueryFilter) ([]QueryRow, int64, error) {
	var where []string
	var args []any
	if f.Domain != "" {
		where = append(where, `q.domain LIKE ?`)
		args = append(args, "%"+f.Domain+"%")
	}
	if f.ClientIP != "" {
		where = append(where, `q.client_ip = ?`)
		args = append(args, f.ClientIP)
	}
	if f.Blocked != nil {
		where = append(where, `q.blocked = ?`)
		args = append(args, boolInt(*f.Blocked))
	}
	if f.QType != nil {
		where = append(where, `q.qtype = ?`)
		args = append(args, *f.QType)
	}
	if !f.Since.IsZero() {
		where = append(where, `q.ts >= ?`)
		args = append(args, f.Since.UnixMilli())
	}
	if !f.Until.IsZero() {
		where = append(where, `q.ts <= ?`)
		args = append(args, f.Until.UnixMilli())
	}
	w := ""
	if len(where) > 0 {
		w = " WHERE " + strings.Join(where, " AND ")
	}
	var total int64
	if err := db.SQL.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM queries q`+w, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	limit := f.Limit
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	rows, err := db.SQL.QueryContext(ctx,
		`SELECT q.id,q.ts,q.client_ip,q.client_id,COALESCE(c.alias,''),q.domain,q.qtype,
		        q.blocked,q.reason,q.rcode,q.latency_ms,q.cached
		 FROM queries q LEFT JOIN clients c ON c.id=q.client_id`+w+
			` ORDER BY q.id DESC LIMIT ? OFFSET ?`,
		append(args, limit, f.Offset)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []QueryRow{}
	for rows.Next() {
		var r QueryRow
		var ts int64
		var blocked, cached int
		if err := rows.Scan(&r.ID, &ts, &r.ClientIP, &r.ClientID, &r.Alias, &r.Domain,
			&r.QType, &blocked, &r.Reason, &r.RCode, &r.LatencyMs, &cached); err != nil {
			return nil, 0, err
		}
		r.Time = time.UnixMilli(ts).UTC().Format(time.RFC3339)
		r.Blocked = blocked != 0
		r.Cached = cached != 0
		out = append(out, r)
	}
	return out, total, rows.Err()
}

// Summary is an aggregate over a time window.
type Summary struct {
	TotalQueries   int64   `json:"total_queries"`
	BlockedQueries int64   `json:"blocked_queries"`
	AllowedQueries int64   `json:"allowed_queries"`
	BlockPct       float64 `json:"block_pct"`
	UniqueDomains  int64   `json:"unique_domains"`
	ActiveClients  int64   `json:"active_clients"`
	CachedQueries  int64   `json:"cached_queries"`
	AvgLatencyMs   float64 `json:"avg_latency_ms"`
}

// StatsSummary aggregates counters since the given time.
func (db *DB) StatsSummary(ctx context.Context, since time.Time) (*Summary, error) {
	var s Summary
	var avg sqlNullFloat
	err := db.SQL.QueryRowContext(ctx,
		`SELECT COUNT(*),
		        COALESCE(SUM(blocked),0),
		        COALESCE(SUM(cached),0),
		        COUNT(DISTINCT domain),
		        COUNT(DISTINCT client_ip),
		        AVG(latency_ms)
		 FROM queries WHERE ts >= ?`, since.UnixMilli()).
		Scan(&s.TotalQueries, &s.BlockedQueries, &s.CachedQueries,
			&s.UniqueDomains, &s.ActiveClients, &avg)
	if err != nil {
		return nil, err
	}
	s.AvgLatencyMs = avg.Float64
	s.AllowedQueries = s.TotalQueries - s.BlockedQueries
	if s.TotalQueries > 0 {
		s.BlockPct = float64(s.BlockedQueries) / float64(s.TotalQueries) * 100
	}
	return &s, nil
}

type sqlNullFloat = sql.NullFloat64

// Bucket is one point of a timeseries.
type Bucket struct {
	Ts      string `json:"ts"`
	Total   int64  `json:"total"`
	Blocked int64  `json:"blocked"`
	Allowed int64  `json:"allowed"`
}

// Timeseries buckets queries between since and now into n intervals.
func (db *DB) Timeseries(ctx context.Context, since time.Time, n int) ([]Bucket, error) {
	if n <= 0 || n > 500 {
		n = 48
	}
	end := time.Now()
	span := end.Sub(since)
	width := int64(span / time.Duration(n) / time.Millisecond)
	if width <= 0 {
		width = 1
	}
	rows, err := db.SQL.QueryContext(ctx,
		`SELECT (ts / ?) AS bucket, COUNT(*), COALESCE(SUM(blocked),0)
		 FROM queries WHERE ts >= ?
		 GROUP BY bucket ORDER BY bucket`, width, since.UnixMilli())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Bucket{}
	for rows.Next() {
		var b, total, blocked int64
		if err := rows.Scan(&b, &total, &blocked); err != nil {
			return nil, err
		}
		out = append(out, Bucket{
			Ts:      time.UnixMilli(b * width).UTC().Format(time.RFC3339),
			Total:   total,
			Blocked: blocked,
			Allowed: total - blocked,
		})
	}
	return out, rows.Err()
}

// TopItem is a ranked domain or client.
type TopItem struct {
	Value   string `json:"value"`
	Total   int64  `json:"total"`
	Blocked int64  `json:"blocked"`
}

// TopDomains ranks domains by query volume; blocked=true ranks only blocked.
func (db *DB) TopDomains(ctx context.Context, since time.Time, blockedOnly bool, limit int) ([]TopItem, error) {
	if limit <= 0 || limit > 100 {
		limit = 10
	}
	w := `WHERE ts >= ?`
	if blockedOnly {
		w += ` AND blocked=1`
	}
	rows, err := db.SQL.QueryContext(ctx,
		`SELECT domain, COUNT(*), COALESCE(SUM(blocked),0) FROM queries `+w+
			` GROUP BY domain ORDER BY COUNT(*) DESC LIMIT ?`, since.UnixMilli(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TopItem
	for rows.Next() {
		var it TopItem
		if err := rows.Scan(&it.Value, &it.Total, &it.Blocked); err != nil {
			return nil, err
		}
		out = append(out, it)
	}
	return out, rows.Err()
}

// TopClients ranks client IPs by query volume.
func (db *DB) TopClients(ctx context.Context, since time.Time, limit int) ([]TopItem, error) {
	if limit <= 0 || limit > 100 {
		limit = 10
	}
	rows, err := db.SQL.QueryContext(ctx,
		`SELECT q.client_ip, COUNT(*), COALESCE(SUM(q.blocked),0)
		 FROM queries q WHERE q.ts >= ?
		 GROUP BY q.client_ip ORDER BY COUNT(*) DESC LIMIT ?`, since.UnixMilli(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TopItem
	for rows.Next() {
		var it TopItem
		if err := rows.Scan(&it.Value, &it.Total, &it.Blocked); err != nil {
			return nil, err
		}
		out = append(out, it)
	}
	return out, rows.Err()
}

// DeleteQueriesBefore removes log rows older than cutoff. Returns rows removed.
func (db *DB) DeleteQueriesBefore(ctx context.Context, cutoff time.Time) (int64, error) {
	res, err := db.SQL.ExecContext(ctx, `DELETE FROM queries WHERE ts < ?`, cutoff.UnixMilli())
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// ---------- Async query writer ----------

// QueryLogger consumes query events from a channel and persists them in
// batches, so the DNS hot path never waits on SQLite. When the channel is
// full the event is dropped and counted.
type QueryLogger struct {
	db      *DB
	ch      chan dnsserver.QueryEvent
	dropped atomic.Int64
	cancel  context.CancelFunc
	wg      sync.WaitGroup

	clientsMu sync.Mutex
	known     map[netip.Addr]int64 // ip -> client id
	knownMiss map[netip.Addr]time.Time
}

// NewQueryLogger returns a logger; call Start to begin consuming.
func NewQueryLogger(db *DB, buf int) *QueryLogger {
	if buf <= 0 {
		buf = 8192
	}
	return &QueryLogger{
		db:        db,
		ch:        make(chan dnsserver.QueryEvent, buf),
		known:     map[netip.Addr]int64{},
		knownMiss: map[netip.Addr]time.Time{},
	}
}

// Submit offers an event for persistence; drops (and counts) when the buffer
// is full so DNS resolution never blocks on the database.
func (q *QueryLogger) Submit(ev dnsserver.QueryEvent) {
	select {
	case q.ch <- ev:
	default:
		q.dropped.Add(1)
	}
}

// Dropped returns the number of events discarded because the buffer was full.
func (q *QueryLogger) Dropped() int64 { return q.dropped.Load() }

// Start launches the consumer goroutine.
func (q *QueryLogger) Start(ctx context.Context) {
	ctx, cancel := context.WithCancel(ctx)
	q.cancel = cancel
	q.wg.Add(1)
	go q.run(ctx)
}

// Stop drains and exits.
func (q *QueryLogger) Stop() {
	if q.cancel != nil {
		q.cancel()
	}
	q.wg.Wait()
}

func (q *QueryLogger) run(ctx context.Context) {
	defer q.wg.Done()
	tick := time.NewTicker(500 * time.Millisecond)
	defer tick.Stop()
	batch := make([]dnsserver.QueryEvent, 0, 512)
	flush := func() {
		if len(batch) == 0 {
			return
		}
		if err := q.insertBatch(context.Background(), batch); err != nil {
			slog.Error("query log write failed", "err", err)
		}
		batch = batch[:0]
	}
	for {
		select {
		case <-ctx.Done():
			// Drain remaining buffered events.
			for {
				select {
				case ev := <-q.ch:
					batch = append(batch, ev)
				default:
					flush()
					return
				}
			}
		case ev := <-q.ch:
			batch = append(batch, ev)
			if len(batch) >= 512 {
				flush()
			}
		case <-tick.C:
			flush()
		}
	}
}

func (q *QueryLogger) insertBatch(ctx context.Context, evs []dnsserver.QueryEvent) error {
	tx, err := q.db.SQL.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	stmt, err := tx.PrepareContext(ctx,
		`INSERT INTO queries(ts,client_ip,client_id,domain,qtype,blocked,reason,rcode,latency_ms,cached)
		 VALUES(?,?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, ev := range evs {
		if _, err := stmt.ExecContext(ctx, ev.Time.UnixMilli(), ev.ClientIP, ev.ClientID,
			ev.Domain, ev.QType, boolInt(ev.Blocked), ev.Reason, ev.RCode, ev.LatencyMs, boolInt(ev.Cached)); err != nil {
			return err
		}
		if err := q.bumpClient(ctx, tx, ev); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (q *QueryLogger) bumpClient(ctx context.Context, tx *sql.Tx, ev dnsserver.QueryEvent) error {
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := tx.ExecContext(ctx,
		`INSERT INTO clients(ip, first_seen, last_seen, total_queries, blocked_queries)
		 VALUES(?,?,?,1,?)
		 ON CONFLICT(ip) DO UPDATE SET
		   last_seen=excluded.last_seen,
		   total_queries=clients.total_queries+1,
		   blocked_queries=clients.blocked_queries+excluded.blocked_queries`,
		ev.ClientIP, now, now, boolInt(ev.Blocked))
	return err
}

// LookupClient resolves an IP to a stable client id, creating the row lazily.
// Results are cached in memory; misses are rate-limited to one DB hit per
// second per IP.
func (q *QueryLogger) LookupClient(ip netip.Addr) int64 {
	q.clientsMu.Lock()
	defer q.clientsMu.Unlock()
	if id, ok := q.known[ip]; ok {
		return id
	}
	if t, ok := q.knownMiss[ip]; ok && time.Since(t) < time.Second {
		return 0
	}
	id, err := q.db.ClientIDByIP(context.Background(), ip)
	if err != nil || id == 0 {
		// Create the row so the client list fills in.
		if _, err2 := q.db.UpsertClientSeen(context.Background(), ip.String(), false); err2 == nil {
			id, _ = q.db.ClientIDByIP(context.Background(), ip)
		}
	}
	if id == 0 {
		q.knownMiss[ip] = time.Now()
		return 0
	}
	q.known[ip] = id
	return id
}

// ForgetClient evicts an ip from the id cache (e.g. after deletion).
func (q *QueryLogger) ForgetClient(ip netip.Addr) {
	q.clientsMu.Lock()
	defer q.clientsMu.Unlock()
	delete(q.known, ip)
}

func formatErr(op string, err error) error { return fmt.Errorf("%s: %w", op, err) }
