// Package database provides SQLite persistence for Blacknet: settings,
// query metadata, clients, blocklists, rules, upstreams and audit events.
package database

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

// DB wraps the sql.DB handle plus helpers.
type DB struct {
	SQL *sql.DB
}

// Open opens (creating if needed) the database at path and runs migrations.
func Open(path string) (*DB, error) {
	dsn := fmt.Sprintf("file:%s?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_pragma=synchronous(NORMAL)", path)
	sqldb, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// Serialize access: SQLite allows a single writer; one connection avoids
	// SQLITE_BUSY surprises and keeps behaviour deterministic.
	sqldb.SetMaxOpenConns(1)
	sqldb.SetConnMaxLifetime(0)
	db := &DB{SQL: sqldb}
	if err := db.migrate(); err != nil {
		sqldb.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return db, nil
}

func (db *DB) Close() error { return db.SQL.Close() }

// Ping reports DB health.
func (db *DB) Ping(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	return db.SQL.PingContext(ctx)
}

var migrations = []string{
	`CREATE TABLE IF NOT EXISTS schema_migrations (
		version INTEGER PRIMARY KEY,
		applied_at TEXT NOT NULL
	)`,
	`CREATE TABLE IF NOT EXISTS settings (
		key TEXT PRIMARY KEY,
		value TEXT NOT NULL
	)`,
	`CREATE TABLE IF NOT EXISTS clients (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		ip TEXT NOT NULL UNIQUE,
		alias TEXT NOT NULL DEFAULT '',
		grp TEXT NOT NULL DEFAULT '',
		first_seen TEXT NOT NULL,
		last_seen TEXT NOT NULL,
		total_queries INTEGER NOT NULL DEFAULT 0,
		blocked_queries INTEGER NOT NULL DEFAULT 0
	)`,
	`CREATE TABLE IF NOT EXISTS queries (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		ts INTEGER NOT NULL,
		client_ip TEXT NOT NULL,
		client_id INTEGER NOT NULL DEFAULT 0,
		domain TEXT NOT NULL,
		qtype INTEGER NOT NULL,
		blocked INTEGER NOT NULL,
		reason TEXT NOT NULL DEFAULT '',
		rcode INTEGER NOT NULL DEFAULT 0,
		latency_ms REAL NOT NULL DEFAULT 0,
		cached INTEGER NOT NULL DEFAULT 0
	)`,
	`CREATE INDEX IF NOT EXISTS idx_queries_ts ON queries(ts)`,
	`CREATE INDEX IF NOT EXISTS idx_queries_domain ON queries(domain)`,
	`CREATE INDEX IF NOT EXISTS idx_queries_client ON queries(client_ip)`,
	`CREATE INDEX IF NOT EXISTS idx_queries_blocked ON queries(blocked, ts)`,
	`CREATE TABLE IF NOT EXISTS blocklists (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		url TEXT NOT NULL UNIQUE,
		enabled INTEGER NOT NULL DEFAULT 1,
		last_refresh TEXT,
		last_error TEXT NOT NULL DEFAULT '',
		rule_count INTEGER NOT NULL DEFAULT 0,
		etag TEXT NOT NULL DEFAULT '',
		last_modified TEXT NOT NULL DEFAULT '',
		content_hash TEXT NOT NULL DEFAULT '',
		created_at TEXT NOT NULL
	)`,
	`CREATE TABLE IF NOT EXISTS blocklist_domains (
		domain TEXT NOT NULL,
		list_id INTEGER NOT NULL,
		allow INTEGER NOT NULL DEFAULT 0,
		PRIMARY KEY (domain, list_id, allow)
	)`,
	`CREATE INDEX IF NOT EXISTS idx_bld_domain ON blocklist_domains(domain)`,
	`CREATE TABLE IF NOT EXISTS rules (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		domain TEXT NOT NULL,
		action TEXT NOT NULL,
		scope TEXT NOT NULL,
		client_id INTEGER NOT NULL DEFAULT 0,
		comment TEXT NOT NULL DEFAULT '',
		enabled INTEGER NOT NULL DEFAULT 1,
		created_at TEXT NOT NULL
	)`,
	`CREATE UNIQUE INDEX IF NOT EXISTS idx_rules_unique ON rules(domain, action, scope, client_id)`,
	`CREATE TABLE IF NOT EXISTS upstreams (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		protocol TEXT NOT NULL,
		address TEXT NOT NULL,
		priority INTEGER NOT NULL DEFAULT 0,
		timeout_ms INTEGER NOT NULL DEFAULT 5000,
		enabled INTEGER NOT NULL DEFAULT 1
	)`,
	`CREATE TABLE IF NOT EXISTS audit (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		ts TEXT NOT NULL,
		action TEXT NOT NULL,
		detail TEXT NOT NULL DEFAULT ''
	)`,
	`CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit(ts)`,
	`CREATE TABLE IF NOT EXISTS dhcp_leases (
		mac TEXT PRIMARY KEY,
		ip TEXT NOT NULL,
		hostname TEXT NOT NULL DEFAULT '',
		expires_at TEXT NOT NULL
	)`,
	// ---------- V2 ----------
	// clients: policy group assignment + identity metadata.
	`ALTER TABLE clients ADD COLUMN policy_group_id INTEGER NOT NULL DEFAULT 0`,
	`ALTER TABLE clients ADD COLUMN classification TEXT NOT NULL DEFAULT 'unknown'`,
	`ALTER TABLE clients ADD COLUMN identity_source TEXT NOT NULL DEFAULT 'dns-observation'`,
	`ALTER TABLE clients ADD COLUMN notes TEXT NOT NULL DEFAULT ''`,
	// queries: resolved policy group at decision time + upstream latency split.
	`ALTER TABLE queries ADD COLUMN group_id INTEGER NOT NULL DEFAULT 0`,
	`ALTER TABLE queries ADD COLUMN upstream_ms REAL NOT NULL DEFAULT 0`,
	`ALTER TABLE queries ADD COLUMN dnssec TEXT NOT NULL DEFAULT ''`,
	`CREATE INDEX IF NOT EXISTS idx_queries_group ON queries(group_id)`,
	// rules: group scope + temporary expiration.
	`ALTER TABLE rules ADD COLUMN group_id INTEGER NOT NULL DEFAULT 0`,
	`ALTER TABLE rules ADD COLUMN expires_at TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE rules ADD COLUMN updated_at TEXT NOT NULL DEFAULT ''`,
	// Widen the dedup key: identical rules may legitimately exist at
	// different scope tiers (global / group / client).
	`DROP INDEX IF EXISTS idx_rules_unique`,
	`CREATE UNIQUE INDEX IF NOT EXISTS idx_rules_unique ON rules(domain, action, scope, client_id, group_id)`,
	// audit: structured fields (older rows stay valid with defaults).
	`ALTER TABLE audit ADD COLUMN actor TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE audit ADD COLUMN resource TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE audit ADD COLUMN result TEXT NOT NULL DEFAULT 'ok'`,
	`CREATE TABLE IF NOT EXISTS policy_groups (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL UNIQUE,
		description TEXT NOT NULL DEFAULT '',
		enabled INTEGER NOT NULL DEFAULT 1,
		upstream_id INTEGER NOT NULL DEFAULT 0,
		created_at TEXT NOT NULL,
		updated_at TEXT NOT NULL
	)`,
	// Maps a client identifier to a policy group. kind: 'client' (stable id),
	// 'ip' (single address), 'cidr' (range). Most specific wins.
	`CREATE TABLE IF NOT EXISTS policy_assignments (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		kind TEXT NOT NULL,
		value TEXT NOT NULL,
		group_id INTEGER NOT NULL REFERENCES policy_groups(id) ON DELETE CASCADE,
		created_at TEXT NOT NULL,
		UNIQUE(kind, value)
	)`,
	// Restricts a blocklist to groups; no rows = global list.
	`CREATE TABLE IF NOT EXISTS group_blocklists (
		group_id INTEGER NOT NULL REFERENCES policy_groups(id) ON DELETE CASCADE,
		blocklist_id INTEGER NOT NULL REFERENCES blocklists(id) ON DELETE CASCADE,
		PRIMARY KEY (group_id, blocklist_id)
	)`,
	`CREATE TABLE IF NOT EXISTS discovery_events (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		kind TEXT NOT NULL,
		value TEXT NOT NULL,
		detail TEXT NOT NULL DEFAULT '',
		first_seen TEXT NOT NULL,
		last_seen TEXT NOT NULL,
		count INTEGER NOT NULL DEFAULT 1,
		notified INTEGER NOT NULL DEFAULT 0,
		UNIQUE(kind, value)
	)`,
	`CREATE TABLE IF NOT EXISTS local_dns_records (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		type TEXT NOT NULL,
		value TEXT NOT NULL,
		ttl INTEGER NOT NULL DEFAULT 300,
		enabled INTEGER NOT NULL DEFAULT 1,
		comment TEXT NOT NULL DEFAULT '',
		created_at TEXT NOT NULL,
		updated_at TEXT NOT NULL
	)`,
	`CREATE INDEX IF NOT EXISTS idx_ldr_name ON local_dns_records(name)`,
	`CREATE TABLE IF NOT EXISTS schedules (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		description TEXT NOT NULL DEFAULT '',
		enabled INTEGER NOT NULL DEFAULT 1,
		tz TEXT NOT NULL DEFAULT 'UTC',
		days_mask INTEGER NOT NULL DEFAULT 127,
		start_min INTEGER NOT NULL DEFAULT 0,
		end_min INTEGER NOT NULL DEFAULT 1439,
		date_from TEXT NOT NULL DEFAULT '',
		date_to TEXT NOT NULL DEFAULT '',
		target_kind TEXT NOT NULL DEFAULT 'group',
		target_id INTEGER NOT NULL DEFAULT 0,
		effect TEXT NOT NULL DEFAULT 'protection_off',
		effect_data TEXT NOT NULL DEFAULT '',
		created_at TEXT NOT NULL,
		updated_at TEXT NOT NULL
	)`,
	`CREATE TABLE IF NOT EXISTS upstream_health (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		upstream_id INTEGER NOT NULL,
		ts TEXT NOT NULL,
		ok INTEGER NOT NULL,
		rtt_ms REAL NOT NULL,
		error TEXT NOT NULL DEFAULT ''
	)`,
	`CREATE INDEX IF NOT EXISTS idx_uh_ts ON upstream_health(upstream_id, ts)`,
	`CREATE TABLE IF NOT EXISTS blocklist_history (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		blocklist_id INTEGER NOT NULL,
		ts TEXT NOT NULL,
		status TEXT NOT NULL,
		rule_count INTEGER NOT NULL DEFAULT 0,
		bytes INTEGER NOT NULL DEFAULT 0,
		malformed INTEGER NOT NULL DEFAULT 0,
		duplicates INTEGER NOT NULL DEFAULT 0,
		hash TEXT NOT NULL DEFAULT '',
		error TEXT NOT NULL DEFAULT ''
	)`,
	`CREATE INDEX IF NOT EXISTS idx_blh_ts ON blocklist_history(blocklist_id, ts)`,
	`CREATE TABLE IF NOT EXISTS enforcement_operations (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		ts TEXT NOT NULL,
		integration TEXT NOT NULL,
		action TEXT NOT NULL,
		status TEXT NOT NULL,
		preview TEXT NOT NULL DEFAULT '',
		result TEXT NOT NULL DEFAULT '',
		actor TEXT NOT NULL DEFAULT ''
	)`,
	`CREATE TABLE IF NOT EXISTS enforcement_backups (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		operation_id INTEGER NOT NULL REFERENCES enforcement_operations(id) ON DELETE CASCADE,
		ts TEXT NOT NULL,
		content TEXT NOT NULL
	)`,
	// Identify a client by more than its current IP (e.g. DHCP MAC binding).
	`CREATE TABLE IF NOT EXISTS client_identities (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		client_id INTEGER NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
		kind TEXT NOT NULL,
		value TEXT NOT NULL,
		created_at TEXT NOT NULL,
		UNIQUE(kind, value)
	)`,
}

func (db *DB) migrate() error {
	var version int
	row := db.SQL.QueryRow(`SELECT COALESCE(MAX(version),0) FROM schema_migrations`)
	if err := row.Scan(&version); err != nil {
		// Table may not exist yet.
		if _, err2 := db.SQL.Exec(migrations[0]); err2 != nil {
			return err2
		}
		version = 0
	}
	for i := version; i < len(migrations); i++ {
		if _, err := db.SQL.Exec(migrations[i]); err != nil {
			return fmt.Errorf("migration %d: %w", i+1, err)
		}
		if _, err := db.SQL.Exec(
			`INSERT INTO schema_migrations(version, applied_at) VALUES(?,?)`,
			i+1, time.Now().UTC().Format(time.RFC3339)); err != nil {
			return err
		}
	}
	return nil
}
