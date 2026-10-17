package database

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"

	"github.com/w0wzahh/blacknet/internal/localdns"
	"github.com/w0wzahh/blacknet/internal/policies"
	"github.com/w0wzahh/blacknet/internal/schedules"
)

func openTest(t *testing.T) *DB {
	t.Helper()
	db, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// TestMigrationFromV1 simulates an existing V1 database: apply only the V1
// migrations on a raw connection, write V1-shaped data, then Open() so the V2
// ALTERs run over live rows. Data must survive and new columns must exist.
func TestMigrationFromV1(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "v1.db")

	// The first 17 migrations are the V1 schema (everything before the V2 block).
	const v1Count = 17
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < v1Count; i++ {
		if _, err := raw.Exec(migrations[i]); err != nil {
			raw.Close()
			t.Fatalf("v1 migration %d: %v", i, err)
		}
		if _, err := raw.Exec(
			`INSERT INTO schema_migrations(version, applied_at) VALUES(?,?)`,
			i+1, "2025-01-01T00:00:00Z"); err != nil {
			raw.Close()
			t.Fatal(err)
		}
	}
	// Seed V1 rows — a client, a rule, a query, an audit line.
	if _, err := raw.Exec(
		`INSERT INTO clients(ip,alias,grp,first_seen,last_seen,total_queries,blocked_queries)
		 VALUES('192.168.1.50','laptop','family','2025-01-01T00:00:00Z','2025-01-02T00:00:00Z',100,12)`); err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(
		`INSERT INTO rules(domain,action,scope,client_id,comment,enabled,created_at)
		 VALUES('ads.example.com','block','tree',0,'v1 rule',1,'2025-01-01T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(
		`INSERT INTO queries(ts,client_ip,client_id,domain,qtype,blocked,reason,rcode,latency_ms,cached)
		 VALUES(1735689600,'192.168.1.50',1,'ads.example.com',1,1,'rule',3,4.5,0)`); err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(
		`INSERT INTO audit(ts,action,detail) VALUES('2025-01-01T00:00:00Z','rule.create','ads.example.com')`); err != nil {
		t.Fatal(err)
	}
	raw.Close()

	// Reopen — V2 migrations apply on top of the V1 schema.
	db, err := Open(path)
	if err != nil {
		t.Fatalf("open migrated db: %v", err)
	}
	defer db.Close()

	// The V1 tables still queryable + V2 tables exist.
	var n int
	for _, table := range []string{
		"clients", "queries", "rules", "blocklists", "upstreams", "audit",
		"policy_groups", "policy_assignments", "group_blocklists",
		"discovery_events", "local_dns_records", "schedules",
		"upstream_health", "blocklist_history",
		"enforcement_operations", "enforcement_backups", "client_identities",
	} {
		if err := db.SQL.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&n); err != nil {
			t.Fatalf("table %s missing after migration: %v", table, err)
		}
	}
	// V2 columns on V1 tables.
	for _, col := range []string{"policy_group_id", "classification", "notes"} {
		if _, err := db.SQL.Exec(`SELECT ` + col + ` FROM clients LIMIT 0`); err != nil {
			t.Fatalf("clients.%s missing: %v", col, err)
		}
	}
	for _, col := range []string{"group_id", "upstream_ms", "dnssec"} {
		if _, err := db.SQL.Exec(`SELECT ` + col + ` FROM queries LIMIT 0`); err != nil {
			t.Fatalf("queries.%s missing: %v", col, err)
		}
	}
	for _, col := range []string{"group_id", "expires_at"} {
		if _, err := db.SQL.Exec(`SELECT ` + col + ` FROM rules LIMIT 0`); err != nil {
			t.Fatalf("rules.%s missing: %v", col, err)
		}
	}
	for _, col := range []string{"actor", "resource", "result"} {
		if _, err := db.SQL.Exec(`SELECT ` + col + ` FROM audit LIMIT 0`); err != nil {
			t.Fatalf("audit.%s missing: %v", col, err)
		}
	}
	// V1 data survived the migration.
	var alias, src string
	if err := db.SQL.QueryRow(
		`SELECT alias, identity_source, policy_group_id FROM clients WHERE ip='192.168.1.50'`).
		Scan(&alias, &src, &n); err != nil {
		t.Fatalf("v1 client row lost: %v", err)
	}
	if alias != "laptop" || src != "dns-observation" || n != 0 {
		t.Fatalf("client mutated: %q %q %d", alias, src, n)
	}
	if err := db.SQL.QueryRow(
		`SELECT COUNT(*) FROM rules WHERE domain='ads.example.com'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("v1 rule lost: %v count=%d", err, n)
	}
	if err := db.SQL.QueryRow(
		`SELECT COUNT(*) FROM queries WHERE domain='ads.example.com'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("v1 query lost: %v count=%d", err, n)
	}
	var res string
	if err := db.SQL.QueryRow(
		`SELECT result FROM audit WHERE action='rule.create'`).Scan(&res); err != nil || res != "ok" {
		t.Fatalf("v1 audit row lost or result wrong: %v result=%q", err, res)
	}
}

func TestPolicyGroupCRUD(t *testing.T) {
	db := openTest(t)
	ctx := context.Background()

	g := policies.Group{Name: "kids", Description: "children's devices", Enabled: true}
	if err := db.CreateGroup(ctx, &g); err != nil {
		t.Fatal(err)
	}
	if g.ID == 0 {
		t.Fatal("expected assigned id")
	}
	got, err := db.GetGroup(ctx, g.ID)
	if err != nil || got.Name != "kids" {
		t.Fatalf("get: %v %+v", err, got)
	}
	// Duplicate name rejected.
	dup := policies.Group{Name: "kids"}
	if err := db.CreateGroup(ctx, &dup); err == nil {
		t.Fatal("expected duplicate error")
	}
	// Update.
	g.Description = "updated"
	if err := db.UpdateGroup(ctx, &g); err != nil {
		t.Fatal(err)
	}
	list, _ := db.ListGroups(ctx)
	if len(list) != 1 || list[0].Description != "updated" {
		t.Fatalf("list: %+v", list)
	}
	// Assignment.
	a := policies.Assignment{Kind: "cidr", Value: "10.0.0.0/8", GroupID: g.ID}
	if err := db.AddAssignment(ctx, &a); err != nil {
		t.Fatal(err)
	}
	as, _ := db.ListAssignments(ctx)
	if len(as) != 1 || as[0].GroupName != "kids" {
		t.Fatalf("assignments: %+v", as)
	}
	// Deleting the group cascades assignments.
	if err := db.DeleteGroup(ctx, g.ID); err != nil {
		t.Fatal(err)
	}
	as, _ = db.ListAssignments(ctx)
	if len(as) != 0 {
		t.Fatal("expected cascade delete of assignments")
	}
}

func TestBlocklistGroupRestriction(t *testing.T) {
	db := openTest(t)
	ctx := context.Background()
	g := policies.Group{Name: "iot"}
	_ = db.CreateGroup(ctx, &g)

	// Need a real blocklist row — group_blocklists has an FK on blocklists(id).
	bl, err := db.AddBlocklist(ctx, "test list", "https://example.org/list.txt")
	if err != nil {
		t.Fatal(err)
	}
	blID := bl.ID

	if err := db.SetBlocklistGroups(ctx, blID, []int64{g.ID}); err != nil {
		t.Fatal(err)
	}
	m, _ := db.ListGroupMap(ctx)
	if len(m[blID]) != 1 || m[blID][0] != g.ID {
		t.Fatalf("group map: %+v", m)
	}
	// Clear = global.
	if err := db.SetBlocklistGroups(ctx, blID, nil); err != nil {
		t.Fatal(err)
	}
	m, _ = db.ListGroupMap(ctx)
	if len(m[blID]) != 0 {
		t.Fatal("expected cleared restriction")
	}
}

func TestLocalRecordCRUD(t *testing.T) {
	db := openTest(t)
	ctx := context.Background()
	rec := localdns.Record{Name: "nas.lan", Type: "A", Value: "192.168.1.10", TTL: 300, Enabled: true}
	if err := db.AddLocalRecord(ctx, &rec); err != nil {
		t.Fatal(err)
	}
	list, _ := db.ListLocalRecords(ctx)
	if len(list) != 1 || list[0].Value != "192.168.1.10" {
		t.Fatalf("records: %+v", list)
	}
	rec.Value = "192.168.1.11"
	if err := db.UpdateLocalRecord(ctx, &rec); err != nil {
		t.Fatal(err)
	}
	if err := db.DeleteLocalRecord(ctx, rec.ID); err != nil {
		t.Fatal(err)
	}
	list, _ = db.ListLocalRecords(ctx)
	if len(list) != 0 {
		t.Fatal("expected empty after delete")
	}
}

func TestScheduleCRUD(t *testing.T) {
	db := openTest(t)
	ctx := context.Background()
	sc := schedules.Schedule{
		Name: "bedtime", Enabled: true, TZ: "UTC",
		DaysMask: 127, StartMin: 21 * 60, EndMin: 7 * 60,
		TargetKind: "protection", Effect: "block_all",
	}
	if err := db.CreateSchedule(ctx, &sc); err != nil {
		t.Fatal(err)
	}
	list, _ := db.ListSchedules(ctx)
	if len(list) != 1 || list[0].StartMin != 21*60 {
		t.Fatalf("schedules: %+v", list)
	}
	sc.Enabled = false
	if err := db.UpdateSchedule(ctx, &sc); err != nil {
		t.Fatal(err)
	}
	if err := db.DeleteSchedule(ctx, sc.ID); err != nil {
		t.Fatal(err)
	}
}

func TestDiscoveryAndIdentities(t *testing.T) {
	db := openTest(t)
	ctx := context.Background()

	fresh, err := db.RecordDiscovery(ctx, "new-ip", "10.0.0.5", "neighbor table")
	if err != nil || !fresh {
		t.Fatalf("record: %v fresh=%v", err, fresh)
	}
	fresh, _ = db.RecordDiscovery(ctx, "new-ip", "10.0.0.5", "neighbor table")
	if fresh {
		t.Fatal("re-observation should not be fresh")
	}
	events, _ := db.ListDiscoveryEvents(ctx, 10)
	if len(events) != 1 || events[0].Count != 2 {
		t.Fatalf("events: %+v", events)
	}
	if err := db.AckDiscoveryEvent(ctx, events[0].ID); err != nil {
		t.Fatal(err)
	}

	// Identities — bind to a real client (FK enforced).
	cid, err := db.UpsertClientSeen(ctx, "10.0.0.9", false)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.BindIdentity(ctx, cid, "mac", "aa:bb:cc:dd:ee:ff"); err != nil {
		t.Fatal(err)
	}
	id, err := db.ClientIDByIdentity(ctx, "mac", "aa:bb:cc:dd:ee:ff")
	if err != nil || id != cid {
		t.Fatalf("lookup: id=%d err=%v", id, err)
	}
	ids, _ := db.ListIdentities(ctx, cid)
	if len(ids) != 1 {
		t.Fatalf("identities: %+v", ids)
	}
	if err := db.UnbindIdentity(ctx, ids[0].ID); err != nil {
		t.Fatal(err)
	}
}

func TestAuditFilterAndRetention(t *testing.T) {
	db := openTest(t)
	ctx := context.Background()
	db.AuditEx(ctx, "admin", "rule.create", "rule:1", "ads.x", "ok")
	db.AuditEx(ctx, "admin", "settings.update", "", "k=v", "ok")
	db.AuditEx(ctx, "system", "enforcement.apply", "openwrt", "plan", "failed")

	items, total, err := db.ListAuditFiltered(ctx, AuditFilter{Actor: "admin"})
	if err != nil || total != 2 || len(items) != 2 {
		t.Fatalf("filtered: %v total=%d len=%d", err, total, len(items))
	}
	items, total, _ = db.ListAuditFiltered(ctx, AuditFilter{Action: "enforcement"})
	if total != 1 || items[0].Result != "failed" {
		t.Fatalf("action filter: %+v", items)
	}
}
