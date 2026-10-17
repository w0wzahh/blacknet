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
