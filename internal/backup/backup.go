// Package backup implements portable backup/restore of Blacknet state as a
// zip archive of JSON files: settings, rules, clients, blocklists, upstreams,
// and optionally query history. Nothing is ever extracted to the filesystem,
// so path traversal is impossible by construction.
package backup

import (
	"archive/zip"
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/w0wzahh/blacknet/internal/database"
)

const manifestName = "manifest.json"

// Manifest describes a backup archive.
type Manifest struct {
	Format          string    `json:"format"` // "blacknet-backup"
	Version         int       `json:"version"`
	CreatedAt       time.Time `json:"created_at"`
	IncludesQueries bool      `json:"includes_queries"`
	Entries         []string  `json:"entries"`
}

var tables = []struct {
	name string
	cols []string
}{
	{"settings", []string{"key", "value"}},
	{"rules", []string{"id", "domain", "action", "scope", "client_id", "comment", "enabled", "created_at"}},
	{"clients", []string{"id", "ip", "alias", "grp", "first_seen", "last_seen", "total_queries", "blocked_queries"}},
	{"blocklists", []string{"id", "name", "url", "enabled", "last_refresh", "last_error", "rule_count", "etag", "last_modified", "content_hash", "created_at"}},
	{"upstreams", []string{"id", "name", "protocol", "address", "priority", "timeout_ms", "enabled"}},
}

// Create writes a backup of db to w. includeQueries adds the query log.
func Create(ctx context.Context, db *database.DB, w io.Writer, includeQueries bool) error {
	zw := zip.NewWriter(w)
	m := Manifest{Format: "blacknet-backup", Version: 1, CreatedAt: time.Now().UTC(), IncludesQueries: includeQueries}
	for _, t := range tables {
		name := t.name + ".json"
		if err := dumpTable(ctx, db, zw, t.name, t.cols, name); err != nil {
			return fmt.Errorf("dump %s: %w", t.name, err)
		}
		m.Entries = append(m.Entries, name)
	}
	if includeQueries {
		if err := dumpQueries(ctx, db, zw); err != nil {
			return err
		}
		m.Entries = append(m.Entries, "queries.json")
	}
	mw, err := zw.Create(manifestName)
	if err != nil {
		return err
	}
	if err := json.NewEncoder(mw).Encode(m); err != nil {
		return err
	}
	return zw.Close()
}

func dumpTable(ctx context.Context, db *database.DB, zw *zip.Writer, table string, cols []string, name string) error {
	f, err := zw.Create(name)
	if err != nil {
		return err
	}
	q := fmt.Sprintf(`SELECT %s FROM "%s"`, joinCols(cols), table)
	rows, err := db.SQL.QueryContext(ctx, q)
	if err != nil {
		return err
	}
	defer rows.Close()
	w := json.NewEncoder(f)
	for rows.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return err
		}
		row := map[string]any{}
		for i, c := range cols {
			row[c] = normalizeSQLValue(vals[i])
		}
		if err := w.Encode(row); err != nil {
			return err
		}
	}
	return rows.Err()
}

func dumpQueries(ctx context.Context, db *database.DB, zw *zip.Writer) error {
	f, err := zw.Create("queries.json")
	if err != nil {
		return err
	}
	rows, err := db.SQL.QueryContext(ctx,
		`SELECT ts,client_ip,client_id,domain,qtype,blocked,reason,rcode,latency_ms,cached FROM queries`)
	if err != nil {
		return err
	}
	defer rows.Close()
	w := json.NewEncoder(f)
	for rows.Next() {
		var ts, clientID, qtype, blocked, rcode, cached int64
		var ip, domain, reason string
		var lat float64
		if err := rows.Scan(&ts, &ip, &clientID, &domain, &qtype, &blocked, &reason, &rcode, &lat, &cached); err != nil {
			return err
		}
		if err := w.Encode(map[string]any{
			"ts": ts, "client_ip": ip, "client_id": clientID, "domain": domain,
			"qtype": qtype, "blocked": blocked, "reason": reason, "rcode": rcode,
			"latency_ms": lat, "cached": cached,
		}); err != nil {
			return err
		}
	}
	return rows.Err()
}

// Inspect validates a backup archive and returns its manifest + a summary of
// what will be replaced. Does not modify the database.
func Inspect(r io.ReaderAt, size int64) (*Manifest, map[string]int, error) {
	zr, err := zip.NewReader(r, size)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid backup archive: %w", err)
	}
	var mf *Manifest
	counts := map[string]int{}
	for _, f := range zr.File {
		// Defence in depth: refuse entries that look like paths.
		if f.Name != manifestName && !isSafeEntry(f.Name) {
			return nil, nil, fmt.Errorf("unexpected entry %q in archive", f.Name)
		}
		rc, err := f.Open()
		if err != nil {
			return nil, nil, err
		}
		if f.Name == manifestName {
			var m Manifest
			if err := json.NewDecoder(io.LimitReader(rc, 1<<20)).Decode(&m); err != nil {
				rc.Close()
				return nil, nil, fmt.Errorf("invalid manifest: %w", err)
			}
			mf = &m
		} else {
			// Count rows.
			dec := json.NewDecoder(io.LimitReader(rc, 512<<20))
			for {
				var v map[string]any
				if err := dec.Decode(&v); err != nil {
					break
				}
				counts[f.Name]++
			}
		}
		rc.Close()
	}
	if mf == nil || mf.Format != "blacknet-backup" {
		return nil, nil, fmt.Errorf("not a blacknet backup archive")
	}
	if mf.Version != 1 {
		return nil, nil, fmt.Errorf("unsupported backup version %d", mf.Version)
	}
	return mf, counts, nil
}

func isSafeEntry(name string) bool {
	for _, t := range tables {
		if name == t.name+".json" {
			return true
		}
	}
	return name == "queries.json"
}

// Restore replaces database contents with the archive contents inside a
// single transaction. Callers should create a safety backup first.
func Restore(ctx context.Context, db *database.DB, data []byte) error {
	mf, _, err := Inspect(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return err
	}
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return err
	}
	tx, err := db.SQL.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, t := range tables {
		if _, err := tx.ExecContext(ctx, fmt.Sprintf(`DELETE FROM "%s"`, t.name)); err != nil {
			return err
		}
		if mf.IncludesQueries && t.name == "settings" {
			// still clear; settings file restores below
		}
	}
	for _, f := range zr.File {
		if f.Name == manifestName {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		err = restoreFile(ctx, tx, f.Name, rc)
		rc.Close()
		if err != nil {
			return fmt.Errorf("restore %s: %w", f.Name, err)
		}
	}
	return tx.Commit()
}

func restoreFile(ctx context.Context, tx *sql.Tx, name string, r io.Reader) error {
	table := name[:len(name)-len(".json")]
	var cols []string
	if table == "queries" {
		cols = []string{"ts", "client_ip", "client_id", "domain", "qtype", "blocked", "reason", "rcode", "latency_ms", "cached"}
		if _, err := tx.ExecContext(ctx, `DELETE FROM queries`); err != nil {
			return err
		}
	} else {
		for _, t := range tables {
			if t.name == table {
				cols = t.cols
			}
		}
		if cols == nil {
			return fmt.Errorf("unknown table %q", table)
		}
	}
	ph := "("
	for i := range cols {
		if i > 0 {
			ph += ","
		}
		ph += "?"
	}
	ph += ")"
	stmt, err := tx.PrepareContext(ctx,
		fmt.Sprintf(`INSERT INTO "%s"(%s) VALUES%s`, table, joinCols(cols), ph))
	if err != nil {
		return err
	}
	defer stmt.Close()
	dec := json.NewDecoder(io.LimitReader(r, 512<<20))
	for {
		var row map[string]any
		if err := dec.Decode(&row); err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		args := make([]any, len(cols))
		for i, c := range cols {
			args[i] = row[c]
		}
		if _, err := stmt.ExecContext(ctx, args...); err != nil {
			return err
		}
	}
}

func joinCols(cols []string) string {
	out := ""
	for i, c := range cols {
		if i > 0 {
			out += ","
		}
		out += `"` + c + `"`
	}
	return out
}

func normalizeSQLValue(v any) any {
	switch t := v.(type) {
	case []byte:
		return string(t)
	default:
		return t
	}
}
