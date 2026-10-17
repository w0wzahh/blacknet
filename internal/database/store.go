package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/netip"
	"time"

	"github.com/w0wzahh/blacknet/internal/filtering"
	"github.com/w0wzahh/blacknet/internal/upstream"
)

// ErrNotFound is returned when a row does not exist.
var ErrNotFound = errors.New("not found")

// ErrDuplicate is returned when a uniqueness constraint is violated.
var ErrDuplicate = errors.New("already exists")

// ---------- Settings ----------

// GetSetting returns a setting decoded into out. Returns false when missing.
func (db *DB) GetSetting(key string, out any) (bool, error) {
	var raw string
	err := db.SQL.QueryRow(`SELECT value FROM settings WHERE key=?`, key).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if out == nil {
		return true, nil
	}
	return true, json.Unmarshal([]byte(raw), out)
}

// SetSetting stores v JSON-encoded under key.
func (db *DB) SetSetting(key string, v any) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = db.SQL.Exec(
		`INSERT INTO settings(key,value) VALUES(?,?)
		 ON CONFLICT(key) DO UPDATE SET value=excluded.value`, key, string(raw))
	return err
}

// AllSettings returns every persisted setting as raw JSON strings.
func (db *DB) AllSettings() (map[string]json.RawMessage, error) {
	rows, err := db.SQL.Query(`SELECT key, value FROM settings`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]json.RawMessage{}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		out[k] = json.RawMessage(v)
	}
	return out, rows.Err()
}

// ---------- Rules ----------

// ListRules returns all user rules.
func (db *DB) ListRules(ctx context.Context) ([]filtering.Rule, error) {
	rows, err := db.SQL.QueryContext(ctx,
		`SELECT id, domain, action, scope, client_id, group_id, comment, enabled, expires_at
		 FROM rules ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []filtering.Rule{}
	for rows.Next() {
		var r filtering.Rule
		var enabled int
		if err := rows.Scan(&r.ID, &r.Domain, &r.Action, &r.Scope, &r.ClientID,
			&r.GroupID, &r.Comment, &enabled, &r.ExpiresAt); err != nil {
			return nil, err
		}
		r.Enabled = enabled != 0
		out = append(out, r)
	}
	return out, rows.Err()
}

// AddRule inserts a user rule.
func (db *DB) AddRule(ctx context.Context, r *filtering.Rule) error {
	now := time.Now().UTC().Format(time.RFC3339)
	res, err := db.SQL.ExecContext(ctx,
		`INSERT INTO rules(domain, action, scope, client_id, group_id, comment, enabled, expires_at, created_at, updated_at)
		 VALUES(?,?,?,?,?,?,?,?,?,?)`,
		filtering.Normalize(r.Domain), string(r.Action), string(r.Scope),
		r.ClientID, r.GroupID, r.Comment, boolInt(r.Enabled), r.ExpiresAt, now, now)
	if err != nil {
		if isUniqueErr(err) {
			return ErrDuplicate
		}
		return err
	}
	r.ID, _ = res.LastInsertId()
	return nil
}

// UpdateRule patches an existing rule.
func (db *DB) UpdateRule(ctx context.Context, r *filtering.Rule) error {
	res, err := db.SQL.ExecContext(ctx,
		`UPDATE rules SET domain=?, action=?, scope=?, client_id=?, group_id=?, comment=?, enabled=?, expires_at=?, updated_at=? WHERE id=?`,
		filtering.Normalize(r.Domain), string(r.Action), string(r.Scope),
		r.ClientID, r.GroupID, r.Comment, boolInt(r.Enabled), r.ExpiresAt,
		time.Now().UTC().Format(time.RFC3339), r.ID)
	if err != nil {
		if isUniqueErr(err) {
			return ErrDuplicate
		}
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteExpiredRules removes temporary rules past their expiry. Returns count.
func (db *DB) DeleteExpiredRules(ctx context.Context, now time.Time) (int64, error) {
	res, err := db.SQL.ExecContext(ctx,
		`DELETE FROM rules WHERE expires_at != '' AND expires_at <= ?`, now.UTC().Format(time.RFC3339))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// DeleteRule removes a rule.
func (db *DB) DeleteRule(ctx context.Context, id int64) error {
	res, err := db.SQL.ExecContext(ctx, `DELETE FROM rules WHERE id=?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// ---------- Blocklists ----------

// Blocklist is a remote rule source.
type Blocklist struct {
	ID           int64  `json:"id"`
	Name         string `json:"name"`
	URL          string `json:"url"`
	Enabled      bool   `json:"enabled"`
	LastRefresh  string `json:"last_refresh,omitempty"`
	LastError    string `json:"last_error,omitempty"`
	RuleCount    int64  `json:"rule_count"`
	ETag         string `json:"-"`
	LastModified string `json:"-"`
	ContentHash  string `json:"content_hash,omitempty"`
	CreatedAt    string `json:"created_at"`
}

// ListBlocklists returns all configured blocklist sources.
func (db *DB) ListBlocklists(ctx context.Context) ([]Blocklist, error) {
	rows, err := db.SQL.QueryContext(ctx,
		`SELECT id,name,url,enabled,COALESCE(last_refresh,''),last_error,rule_count,etag,last_modified,content_hash,created_at
		 FROM blocklists ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Blocklist{}
	for rows.Next() {
		var b Blocklist
		var en int
		if err := rows.Scan(&b.ID, &b.Name, &b.URL, &en, &b.LastRefresh, &b.LastError,
			&b.RuleCount, &b.ETag, &b.LastModified, &b.ContentHash, &b.CreatedAt); err != nil {
			return nil, err
		}
		b.Enabled = en != 0
		out = append(out, b)
	}
	return out, rows.Err()
}

// GetBlocklist returns one list.
func (db *DB) GetBlocklist(ctx context.Context, id int64) (*Blocklist, error) {
	var b Blocklist
	var en int
	err := db.SQL.QueryRowContext(ctx,
		`SELECT id,name,url,enabled,COALESCE(last_refresh,''),last_error,rule_count,etag,last_modified,content_hash,created_at
		 FROM blocklists WHERE id=?`, id).
		Scan(&b.ID, &b.Name, &b.URL, &en, &b.LastRefresh, &b.LastError,
			&b.RuleCount, &b.ETag, &b.LastModified, &b.ContentHash, &b.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	b.Enabled = en != 0
	return &b, nil
}

// AddBlocklist inserts a new source.
func (db *DB) AddBlocklist(ctx context.Context, name, url string) (*Blocklist, error) {
	res, err := db.SQL.ExecContext(ctx,
		`INSERT INTO blocklists(name,url,created_at) VALUES(?,?,?)`,
		name, url, time.Now().UTC().Format(time.RFC3339))
	if err != nil {
		if isUniqueErr(err) {
			return nil, ErrDuplicate
		}
		return nil, err
	}
	id, _ := res.LastInsertId()
	return db.GetBlocklist(ctx, id)
}

// UpdateBlocklistState records refresh outcome and replaces a list's domains
// inside a single transaction. Pass nil domains to only update state fields
// (e.g. failed refresh).
func (db *DB) UpdateBlocklistState(ctx context.Context, id int64, lastErr string,
	etag, lastMod, hash string, domains *BlocklistDomains) error {
	tx, err := db.SQL.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if domains != nil {
		if _, err := tx.ExecContext(ctx, `DELETE FROM blocklist_domains WHERE list_id=?`, id); err != nil {
			return err
		}
		stmt, err := tx.PrepareContext(ctx,
			`INSERT OR IGNORE INTO blocklist_domains(domain,list_id,allow) VALUES(?,?,?)`)
		if err != nil {
			return err
		}
		defer stmt.Close()
		for d := range domains.Blocks {
			if _, err := stmt.ExecContext(ctx, d, id, 0); err != nil {
				return err
			}
		}
		for d := range domains.Allows {
			if _, err := stmt.ExecContext(ctx, d, id, 1); err != nil {
				return err
			}
		}
	}
	var q string
	var args []any
	if domains != nil {
		q = `UPDATE blocklists SET last_refresh=?, last_error=?, rule_count=?, etag=?, last_modified=?, content_hash=? WHERE id=?`
		args = []any{time.Now().UTC().Format(time.RFC3339), lastErr, int64(len(domains.Blocks)), etag, lastMod, hash, id}
	} else {
		q = `UPDATE blocklists SET last_error=? WHERE id=?`
		args = []any{lastErr, id}
	}
	if _, err := tx.ExecContext(ctx, q, args...); err != nil {
		return err
	}
	return tx.Commit()
}

// SetBlocklistEnabled toggles a list.
func (db *DB) SetBlocklistEnabled(ctx context.Context, id int64, on bool) error {
	res, err := db.SQL.ExecContext(ctx, `UPDATE blocklists SET enabled=? WHERE id=?`, boolInt(on), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// RenameBlocklist updates name/url.
func (db *DB) RenameBlocklist(ctx context.Context, id int64, name, url string) error {
	res, err := db.SQL.ExecContext(ctx, `UPDATE blocklists SET name=?, url=? WHERE id=?`, name, url, id)
	if err != nil {
		if isUniqueErr(err) {
			return ErrDuplicate
		}
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteBlocklist removes a list and its imported domains.
func (db *DB) DeleteBlocklist(ctx context.Context, id int64) error {
	tx, err := db.SQL.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `DELETE FROM blocklists WHERE id=?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM blocklist_domains WHERE list_id=?`, id); err != nil {
		return err
	}
	return tx.Commit()
}

// BlocklistDomains holds parsed domains from a list.
type BlocklistDomains struct {
	Blocks map[string]struct{}
	Allows map[string]struct{}
}

// ImportedDomains aggregates domains across enabled lists into engine maps.
func (db *DB) ImportedDomains(ctx context.Context) (blocks, allows map[string]int64, err error) {
	rows, err := db.SQL.QueryContext(ctx,
		`SELECT d.domain, d.list_id, d.allow FROM blocklist_domains d
		 JOIN blocklists b ON b.id=d.list_id WHERE b.enabled=1`)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	blocks = map[string]int64{}
	allows = map[string]int64{}
	for rows.Next() {
		var dom string
		var listID int64
		var allow int
		if err := rows.Scan(&dom, &listID, &allow); err != nil {
			return nil, nil, err
		}
		if allow != 0 {
			if _, seen := allows[dom]; !seen {
				allows[dom] = listID
			}
		} else if _, seen := blocks[dom]; !seen {
			blocks[dom] = listID
		}
	}
	return blocks, allows, rows.Err()
}

// ListDomains returns one list's block domains (for overlap analysis).
func (db *DB) ListDomains(ctx context.Context, listID int64) (map[string]struct{}, error) {
	rows, err := db.SQL.QueryContext(ctx,
		`SELECT domain FROM blocklist_domains WHERE list_id=? AND allow=0`, listID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]struct{}{}
	for rows.Next() {
		var d string
		if err := rows.Scan(&d); err != nil {
			return nil, err
		}
		out[d] = struct{}{}
	}
	return out, rows.Err()
}

// ---------- Upstreams ----------

// ListUpstreams returns resolver rows.
func (db *DB) ListUpstreams(ctx context.Context) ([]upstream.Config, error) {
	rows, err := db.SQL.QueryContext(ctx,
		`SELECT id,name,protocol,address,priority,timeout_ms,enabled FROM upstreams ORDER BY priority, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []upstream.Config{}
	for rows.Next() {
		var c upstream.Config
		var en int
		var to int64
		if err := rows.Scan(&c.ID, &c.Name, &c.Protocol, &c.Address, &c.Priority, &to, &en); err != nil {
			return nil, err
		}
		c.Timeout = time.Duration(to) * time.Millisecond
		c.Enabled = en != 0
		out = append(out, c)
	}
	return out, rows.Err()
}

// AddUpstream inserts a resolver.
func (db *DB) AddUpstream(ctx context.Context, c *upstream.Config) error {
	res, err := db.SQL.ExecContext(ctx,
		`INSERT INTO upstreams(name,protocol,address,priority,timeout_ms,enabled) VALUES(?,?,?,?,?,?)`,
		c.Name, string(c.Protocol), c.Address, c.Priority, c.Timeout.Milliseconds(), boolInt(c.Enabled))
	if err != nil {
		return err
	}
	c.ID, _ = res.LastInsertId()
	return nil
}

// UpdateUpstream patches a resolver row.
func (db *DB) UpdateUpstream(ctx context.Context, c *upstream.Config) error {
	res, err := db.SQL.ExecContext(ctx,
		`UPDATE upstreams SET name=?,protocol=?,address=?,priority=?,timeout_ms=?,enabled=? WHERE id=?`,
		c.Name, string(c.Protocol), c.Address, c.Priority, c.Timeout.Milliseconds(), boolInt(c.Enabled), c.ID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteUpstream removes a resolver.
func (db *DB) DeleteUpstream(ctx context.Context, id int64) error {
	res, err := db.SQL.ExecContext(ctx, `DELETE FROM upstreams WHERE id=?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// ---------- Clients ----------

// Client is a known source of DNS queries (a device).
type Client struct {
	ID             int64  `json:"id"`
	IP             string `json:"ip"`
	Alias          string `json:"alias"`
	Group          string `json:"group"` // legacy free-text label
	PolicyGroupID  int64  `json:"policy_group_id"`
	PolicyGroup    string `json:"policy_group,omitempty"`
	Classification string `json:"classification"`
	IdentitySource string `json:"identity_source"`
	Notes          string `json:"notes"`
	FirstSeen      string `json:"first_seen"`
	LastSeen       string `json:"last_seen"`
	TotalQueries   int64  `json:"total_queries"`
	BlockedQueries int64  `json:"blocked_queries"`
}

const clientCols = `c.id,c.ip,c.alias,c.grp,c.policy_group_id,c.classification,
	c.identity_source,c.notes,c.first_seen,c.last_seen,c.total_queries,c.blocked_queries`

func scanClient(row interface{ Scan(...any) error }) (*Client, error) {
	var c Client
	if err := row.Scan(&c.ID, &c.IP, &c.Alias, &c.Group, &c.PolicyGroupID,
		&c.Classification, &c.IdentitySource, &c.Notes, &c.FirstSeen, &c.LastSeen,
		&c.TotalQueries, &c.BlockedQueries); err != nil {
		return nil, err
	}
	return &c, nil
}

// ListClients returns all known clients.
func (db *DB) ListClients(ctx context.Context) ([]Client, error) {
	rows, err := db.SQL.QueryContext(ctx,
		`SELECT `+clientCols+` FROM clients c ORDER BY c.last_seen DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Client{}
	for rows.Next() {
		c, err := scanClient(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *c)
	}
	return out, rows.Err()
}

// GetClient returns one client, with its policy-group name resolved.
func (db *DB) GetClient(ctx context.Context, id int64) (*Client, error) {
	row := db.SQL.QueryRowContext(ctx,
		`SELECT `+clientCols+`, COALESCE(g.name,'')
		 FROM clients c LEFT JOIN policy_groups g ON g.id=c.policy_group_id
		 WHERE c.id=?`, id)
	var c Client
	if err := row.Scan(&c.ID, &c.IP, &c.Alias, &c.Group, &c.PolicyGroupID,
		&c.Classification, &c.IdentitySource, &c.Notes, &c.FirstSeen, &c.LastSeen,
		&c.TotalQueries, &c.BlockedQueries, &c.PolicyGroup); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &c, nil
}

// ClientUpdate is a patch for a device row.
type ClientUpdate struct {
	Alias          string `json:"alias"`
	Group          string `json:"group"`
	PolicyGroupID  int64  `json:"policy_group_id"`
	Classification string `json:"classification"`
	Notes          string `json:"notes"`
}

// UpdateClient patches alias/group/policy/classification/notes.
func (db *DB) UpdateClient(ctx context.Context, id int64, u ClientUpdate) error {
	res, err := db.SQL.ExecContext(ctx,
		`UPDATE clients SET alias=?, grp=?, policy_group_id=?, classification=?, notes=? WHERE id=?`,
		u.Alias, u.Group, u.PolicyGroupID, u.Classification, u.Notes, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// ClientGroupMap returns client_id -> policy_group_id for every row.
func (db *DB) ClientGroupMap(ctx context.Context) (map[int64]int64, error) {
	rows, err := db.SQL.QueryContext(ctx, `SELECT id, policy_group_id FROM clients`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64]int64{}
	for rows.Next() {
		var id, gid int64
		if err := rows.Scan(&id, &gid); err != nil {
			return nil, err
		}
		out[id] = gid
	}
	return out, rows.Err()
}

// DeleteClient forgets a client and its statistics.
func (db *DB) DeleteClient(ctx context.Context, id int64) error {
	res, err := db.SQL.ExecContext(ctx, `DELETE FROM clients WHERE id=?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// ResetClientStats zeroes a client's counters.
func (db *DB) ResetClientStats(ctx context.Context, id int64) error {
	res, err := db.SQL.ExecContext(ctx,
		`UPDATE clients SET total_queries=0, blocked_queries=0 WHERE id=?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// UpsertClientSeen records activity; returns the client id.
func (db *DB) UpsertClientSeen(ctx context.Context, ip string, blocked bool) (int64, error) {
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := db.SQL.ExecContext(ctx,
		`INSERT INTO clients(ip, first_seen, last_seen, total_queries, blocked_queries)
		 VALUES(?,?,?,1,?)
		 ON CONFLICT(ip) DO UPDATE SET
		   last_seen=excluded.last_seen,
		   total_queries=clients.total_queries+1,
		   blocked_queries=clients.blocked_queries+excluded.blocked_queries`,
		ip, now, now, boolInt(blocked))
	if err != nil {
		return 0, err
	}
	var id int64
	err = db.SQL.QueryRowContext(ctx, `SELECT id FROM clients WHERE ip=?`, ip).Scan(&id)
	return id, err
}

// ClientIDByIP returns the id for an IP, 0 when unknown.
func (db *DB) ClientIDByIP(ctx context.Context, ip netip.Addr) (int64, error) {
	var id int64
	err := db.SQL.QueryRowContext(ctx, `SELECT id FROM clients WHERE ip=?`, ip.String()).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	return id, err
}

// ---------- DHCP leases ----------

// LoadLeases returns all persisted DHCP leases.
func (db *DB) LoadLeases(ctx context.Context) ([]struct {
	MAC, IP, Hostname string
	ExpiresAt         time.Time
}, error) {
	rows, err := db.SQL.QueryContext(ctx, `SELECT mac, ip, hostname, expires_at FROM dhcp_leases`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	type L = struct {
		MAC, IP, Hostname string
		ExpiresAt         time.Time
	}
	var out []L
	for rows.Next() {
		var l L
		var exp string
		if err := rows.Scan(&l.MAC, &l.IP, &l.Hostname, &exp); err != nil {
			return nil, err
		}
		l.ExpiresAt, _ = time.Parse(time.RFC3339, exp)
		out = append(out, l)
	}
	return out, rows.Err()
}

// SaveLease upserts a lease.
func (db *DB) SaveLease(ctx context.Context, mac, ip, hostname string, expiresAt time.Time) error {
	_, err := db.SQL.ExecContext(ctx,
		`INSERT INTO dhcp_leases(mac,ip,hostname,expires_at) VALUES(?,?,?,?)
		 ON CONFLICT(mac) DO UPDATE SET ip=excluded.ip, hostname=excluded.hostname, expires_at=excluded.expires_at`,
		mac, ip, hostname, expiresAt.UTC().Format(time.RFC3339))
	return err
}

// DeleteLease removes a lease.
func (db *DB) DeleteLease(ctx context.Context, mac string) error {
	_, err := db.SQL.ExecContext(ctx, `DELETE FROM dhcp_leases WHERE mac=?`, mac)
	return err
}

// ---------- Audit ----------

// Audit writes an audit event.
func (db *DB) Audit(ctx context.Context, action, detail string) {
	_, _ = db.SQL.ExecContext(ctx, `INSERT INTO audit(ts,action,detail) VALUES(?,?,?)`,
		time.Now().UTC().Format(time.RFC3339), action, detail)
}

// ListAudit returns recent audit entries.
func (db *DB) ListAudit(ctx context.Context, limit int) ([]map[string]any, error) {
	rows, err := db.SQL.QueryContext(ctx,
		`SELECT ts, action, detail FROM audit ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var ts, a, d string
		if err := rows.Scan(&ts, &a, &d); err != nil {
			return nil, err
		}
		out = append(out, map[string]any{"ts": ts, "action": a, "detail": d})
	}
	return out, rows.Err()
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func isUniqueErr(err error) bool {
	return err != nil && (contains(err.Error(), "UNIQUE constraint") || contains(err.Error(), "constraint failed"))
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()
}
