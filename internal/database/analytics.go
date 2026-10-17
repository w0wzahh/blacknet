package database

import (
	"context"
	"time"
)

// LatencyStats summarizes resolution latency over a window.
type LatencyStats struct {
	Count         int64   `json:"count"`
	AvgMs         float64 `json:"avg_ms"`
	P50Ms         float64 `json:"p50_ms"`
	P95Ms         float64 `json:"p95_ms"`
	AvgUpstreamMs float64 `json:"avg_upstream_ms"`
}

// StatsLatency computes percentiles from stored query rows.
func (db *DB) StatsLatency(ctx context.Context, since time.Time) (*LatencyStats, error) {
	var s LatencyStats
	var avgU float64
	err := db.SQL.QueryRowContext(ctx,
		`SELECT COUNT(*), COALESCE(AVG(latency_ms),0), COALESCE(AVG(upstream_ms),0)
		 FROM queries WHERE ts >= ?`, since.UnixMilli()).
		Scan(&s.Count, &s.AvgMs, &avgU)
	if err != nil {
		return nil, err
	}
	s.AvgUpstreamMs = avgU
	// Percentiles via ORDER BY + OFFSET on the latency column (bounded rows).
	pct := func(p float64) float64 {
		if s.Count == 0 {
			return 0
		}
		off := int64(float64(s.Count) * p)
		if off >= s.Count {
			off = s.Count - 1
		}
		var v float64
		if err := db.SQL.QueryRowContext(ctx,
			`SELECT latency_ms FROM queries WHERE ts >= ? ORDER BY latency_ms LIMIT 1 OFFSET ?`,
			since.UnixMilli(), off).Scan(&v); err != nil {
			return 0
		}
		return v
	}
	s.P50Ms = pct(0.50)
	s.P95Ms = pct(0.95)
	return &s, nil
}

// RCodeStat counts responses per rcode over a window.
type RCodeStat struct {
	RCode int    `json:"rcode"`
	Name  string `json:"name"`
	Total int64  `json:"total"`
}

// StatsErrors groups queries by response code in the window.
func (db *DB) StatsErrors(ctx context.Context, since time.Time) ([]RCodeStat, error) {
	rows, err := db.SQL.QueryContext(ctx,
		`SELECT rcode, COUNT(*) FROM queries WHERE ts >= ? GROUP BY rcode ORDER BY COUNT(*) DESC`,
		since.UnixMilli())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []RCodeStat{}
	for rows.Next() {
		var s RCodeStat
		if err := rows.Scan(&s.RCode, &s.Total); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// GroupStat is per-policy-group traffic.
type GroupStat struct {
	GroupID int64  `json:"group_id"`
	Name    string `json:"name"`
	Total   int64  `json:"total"`
	Blocked int64  `json:"blocked"`
	Clients int64  `json:"clients"`
}

// StatsByGroup aggregates queries per resolved group.
func (db *DB) StatsByGroup(ctx context.Context, since time.Time) ([]GroupStat, error) {
	rows, err := db.SQL.QueryContext(ctx,
		`SELECT q.group_id, COALESCE(g.name,''), COUNT(*), COALESCE(SUM(q.blocked),0),
		        COUNT(DISTINCT q.client_ip)
		 FROM queries q LEFT JOIN policy_groups g ON g.id=q.group_id
		 WHERE q.ts >= ? GROUP BY q.group_id ORDER BY COUNT(*) DESC`, since.UnixMilli())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []GroupStat{}
	for rows.Next() {
		var s GroupStat
		if err := rows.Scan(&s.GroupID, &s.Name, &s.Total, &s.Blocked, &s.Clients); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// DomainStats is the investigation view for one domain.
type DomainStats struct {
	Domain     string           `json:"domain"`
	Total      int64            `json:"total"`
	Blocked    int64            `json:"blocked"`
	FirstSeen  string           `json:"first_seen,omitempty"`
	LastSeen   string           `json:"last_seen,omitempty"`
	TopClients []TopItem        `json:"top_clients"`
	RCodes     map[int]int64    `json:"rcodes"`
	Reasons    map[string]int64 `json:"reasons"`
}

// StatsDomain aggregates everything known about one domain.
func (db *DB) StatsDomain(ctx context.Context, domain string) (*DomainStats, error) {
	var s DomainStats
	s.Domain = domain
	s.TopClients = []TopItem{}
	s.RCodes = map[int]int64{}
	s.Reasons = map[string]int64{}
	var first, last int64
	err := db.SQL.QueryRowContext(ctx,
		`SELECT COUNT(*), COALESCE(SUM(blocked),0), COALESCE(MIN(ts),0), COALESCE(MAX(ts),0)
		 FROM queries WHERE domain=?`, domain).
		Scan(&s.Total, &s.Blocked, &first, &last)
	if err != nil {
		return nil, err
	}
	if first > 0 {
		s.FirstSeen = time.UnixMilli(first).UTC().Format(time.RFC3339)
		s.LastSeen = time.UnixMilli(last).UTC().Format(time.RFC3339)
	}
	rows, err := db.SQL.QueryContext(ctx,
		`SELECT client_ip, COUNT(*), COALESCE(SUM(blocked),0) FROM queries
		 WHERE domain=? GROUP BY client_ip ORDER BY COUNT(*) DESC LIMIT 10`, domain)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var it TopItem
		if err := rows.Scan(&it.Value, &it.Total, &it.Blocked); err != nil {
			rows.Close()
			return nil, err
		}
		s.TopClients = append(s.TopClients, it)
	}
	rows.Close()
	rows, err = db.SQL.QueryContext(ctx,
		`SELECT rcode, COUNT(*) FROM queries WHERE domain=? GROUP BY rcode`, domain)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var rc, n int64
		if err := rows.Scan(&rc, &n); err != nil {
			rows.Close()
			return nil, err
		}
		s.RCodes[int(rc)] = n
	}
	rows.Close()
	rows, err = db.SQL.QueryContext(ctx,
		`SELECT reason, COUNT(*) FROM queries WHERE domain=? GROUP BY reason`, domain)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var rs string
		var n int64
		if err := rows.Scan(&rs, &n); err != nil {
			return nil, err
		}
		s.Reasons[rs] = n
	}
	return &s, rows.Err()
}

// ClientTimeseries buckets one client's queries.
func (db *DB) ClientTimeseries(ctx context.Context, clientID int64, since time.Time, n int) ([]Bucket, error) {
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
		 FROM queries WHERE ts >= ? AND client_id = ?
		 GROUP BY bucket ORDER BY bucket`, width, since.UnixMilli(), clientID)
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

// ClientTopDomains ranks domains for one client.
func (db *DB) ClientTopDomains(ctx context.Context, clientID int64, since time.Time, blockedOnly bool, limit int) ([]TopItem, error) {
	if limit <= 0 || limit > 100 {
		limit = 10
	}
	w := `WHERE ts >= ? AND client_id = ?`
	if blockedOnly {
		w += ` AND blocked=1`
	}
	rows, err := db.SQL.QueryContext(ctx,
		`SELECT domain, COUNT(*), COALESCE(SUM(blocked),0) FROM queries `+w+
			` GROUP BY domain ORDER BY COUNT(*) DESC LIMIT ?`, since.UnixMilli(), clientID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []TopItem{}
	for rows.Next() {
		var it TopItem
		if err := rows.Scan(&it.Value, &it.Total, &it.Blocked); err != nil {
			return nil, err
		}
		out = append(out, it)
	}
	return out, rows.Err()
}
