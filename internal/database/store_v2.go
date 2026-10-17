package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/w0wzahh/blacknet/internal/localdns"
	"github.com/w0wzahh/blacknet/internal/policies"
	"github.com/w0wzahh/blacknet/internal/schedules"
)

func nowUTC() string { return time.Now().UTC().Format(time.RFC3339) }

// ---------- Policy groups ----------

func scanGroup(row interface{ Scan(...any) error }) (*policies.Group, error) {
	var g policies.Group
	var en int
	err := row.Scan(&g.ID, &g.Name, &g.Description, &en, &g.UpstreamID,
		&g.CreatedAt, &g.UpdatedAt)
	g.Enabled = en != 0
	return &g, err
}

const groupCols = `id,name,description,enabled,upstream_id,created_at,updated_at`

// ListGroups returns every policy group with member and list counts.
func (db *DB) ListGroups(ctx context.Context) ([]policies.Group, error) {
	rows, err := db.SQL.QueryContext(ctx,
		`SELECT g.id,g.name,g.description,g.enabled,g.upstream_id,g.created_at,g.updated_at,
		        (SELECT COUNT(*) FROM clients c WHERE c.policy_group_id=g.id),
		        (SELECT GROUP_CONCAT(blocklist_id) FROM group_blocklists gb WHERE gb.group_id=g.id)
		 FROM policy_groups g ORDER BY g.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []policies.Group{}
	for rows.Next() {
		var g policies.Group
		var en, n int
		var lists sql.NullString
		if err := rows.Scan(&g.ID, &g.Name, &g.Description, &en, &g.UpstreamID,
			&g.CreatedAt, &g.UpdatedAt, &n, &lists); err != nil {
			return nil, err
		}
		g.Enabled = en != 0
		g.ClientCount = n
		if lists.Valid {
			for _, s := range splitCSV(lists.String) {
				var id int64
				if _, err := fmt.Sscan(s, &id); err == nil {
					g.ListIDs = append(g.ListIDs, id)
				}
			}
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// GetGroup returns one group.
func (db *DB) GetGroup(ctx context.Context, id int64) (*policies.Group, error) {
	g, err := scanGroup(db.SQL.QueryRowContext(ctx,
		`SELECT `+groupCols+` FROM policy_groups WHERE id=?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return g, err
}

// CreateGroup inserts a group.
func (db *DB) CreateGroup(ctx context.Context, g *policies.Group) error {
	res, err := db.SQL.ExecContext(ctx,
		`INSERT INTO policy_groups(name,description,enabled,upstream_id,created_at,updated_at)
		 VALUES(?,?,?,?,?,?)`,
		g.Name, g.Description, boolInt(g.Enabled), g.UpstreamID, nowUTC(), nowUTC())
	if err != nil {
		if isUniqueErr(err) {
			return ErrDuplicate
		}
		return err
	}
	g.ID, _ = res.LastInsertId()
	return nil
}

// UpdateGroup patches a group.
func (db *DB) UpdateGroup(ctx context.Context, g *policies.Group) error {
	res, err := db.SQL.ExecContext(ctx,
		`UPDATE policy_groups SET name=?,description=?,enabled=?,upstream_id=?,updated_at=? WHERE id=?`,
		g.Name, g.Description, boolInt(g.Enabled), g.UpstreamID, nowUTC(), g.ID)
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

// DeleteGroup removes a group; members revert to the default group.
func (db *DB) DeleteGroup(ctx context.Context, id int64) error {
	tx, err := db.SQL.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx,
		`UPDATE clients SET policy_group_id=0 WHERE policy_group_id=?`, id); err != nil {
		return err
	}
	res, err := tx.ExecContext(ctx, `DELETE FROM policy_groups WHERE id=?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return tx.Commit()
}

// ---------- Assignments ----------

// ListAssignments returns all ip/cidr assignments with group names.
func (db *DB) ListAssignments(ctx context.Context) ([]policies.Assignment, error) {
	rows, err := db.SQL.QueryContext(ctx,
		`SELECT a.id,a.kind,a.value,a.group_id,COALESCE(g.name,''),a.created_at
		 FROM policy_assignments a LEFT JOIN policy_groups g ON g.id=a.group_id
		 ORDER BY a.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []policies.Assignment{}
	for rows.Next() {
		var a policies.Assignment
		if err := rows.Scan(&a.ID, &a.Kind, &a.Value, &a.GroupID, &a.GroupName, &a.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// AddAssignment inserts an ip/cidr assignment.
func (db *DB) AddAssignment(ctx context.Context, a *policies.Assignment) error {
	res, err := db.SQL.ExecContext(ctx,
		`INSERT INTO policy_assignments(kind,value,group_id,created_at) VALUES(?,?,?,?)`,
		a.Kind, a.Value, a.GroupID, nowUTC())
	if err != nil {
		if isUniqueErr(err) {
			return ErrDuplicate
		}
		return err
	}
	a.ID, _ = res.LastInsertId()
	return nil
}

// DeleteAssignment removes an assignment row.
func (db *DB) DeleteAssignment(ctx context.Context, id int64) error {
	res, err := db.SQL.ExecContext(ctx, `DELETE FROM policy_assignments WHERE id=?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// ---------- Group <-> blocklist ----------

// ListGroupMap returns blocklist_id -> [group ids] (no rows = global list).
func (db *DB) ListGroupMap(ctx context.Context) (map[int64][]int64, error) {
	rows, err := db.SQL.QueryContext(ctx,
		`SELECT blocklist_id, group_id FROM group_blocklists`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64][]int64{}
	for rows.Next() {
		var bid, gid int64
		if err := rows.Scan(&bid, &gid); err != nil {
			return nil, err
		}
		out[bid] = append(out[bid], gid)
	}
	return out, rows.Err()
}

// SetBlocklistGroups replaces a list's group restriction atomically.
// An empty slice makes the list global again.
func (db *DB) SetBlocklistGroups(ctx context.Context, blocklistID int64, groupIDs []int64) error {
	tx, err := db.SQL.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM group_blocklists WHERE blocklist_id=?`, blocklistID); err != nil {
		return err
	}
	for _, g := range groupIDs {
		if _, err := tx.ExecContext(ctx,
			`INSERT OR IGNORE INTO group_blocklists(group_id,blocklist_id) VALUES(?,?)`,
			g, blocklistID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// ---------- Schedules ----------

const schedCols = `id,name,description,enabled,tz,days_mask,start_min,end_min,
	date_from,date_to,target_kind,target_id,effect,effect_data,created_at,updated_at`

func scanSched(row interface{ Scan(...any) error }) (*schedules.Schedule, error) {
	var s schedules.Schedule
	var en int
	var effectData string
	err := row.Scan(&s.ID, &s.Name, &s.Description, &en, &s.TZ, &s.DaysMask,
		&s.StartMin, &s.EndMin, &s.DateFrom, &s.DateTo, &s.TargetKind, &s.TargetID,
		&s.Effect, &effectData, &s.CreatedAt, &s.UpdatedAt)
	s.Enabled = en != 0
	s.ListIDs = schedules.DecodeListIDs(effectData)
	return &s, err
}

// ListSchedules returns all schedules.
func (db *DB) ListSchedules(ctx context.Context) ([]schedules.Schedule, error) {
	rows, err := db.SQL.QueryContext(ctx, `SELECT `+schedCols+` FROM schedules ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []schedules.Schedule{}
	for rows.Next() {
		s, err := scanSched(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *s)
	}
	return out, rows.Err()
}

// GetSchedule returns one schedule.
func (db *DB) GetSchedule(ctx context.Context, id int64) (*schedules.Schedule, error) {
	s, err := scanSched(db.SQL.QueryRowContext(ctx,
		`SELECT `+schedCols+` FROM schedules WHERE id=?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return s, err
}

// CreateSchedule inserts a schedule.
func (db *DB) CreateSchedule(ctx context.Context, s *schedules.Schedule) error {
	res, err := db.SQL.ExecContext(ctx,
		`INSERT INTO schedules(name,description,enabled,tz,days_mask,start_min,end_min,
			date_from,date_to,target_kind,target_id,effect,effect_data,created_at,updated_at)
		 VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		s.Name, s.Description, boolInt(s.Enabled), s.TZ, s.DaysMask, s.StartMin, s.EndMin,
		s.DateFrom, s.DateTo, s.TargetKind, s.TargetID, s.Effect,
		schedules.EncodeListIDs(s.ListIDs), nowUTC(), nowUTC())
	if err != nil {
		return err
	}
	s.ID, _ = res.LastInsertId()
	return nil
}

// UpdateSchedule patches a schedule.
func (db *DB) UpdateSchedule(ctx context.Context, s *schedules.Schedule) error {
	res, err := db.SQL.ExecContext(ctx,
		`UPDATE schedules SET name=?,description=?,enabled=?,tz=?,days_mask=?,start_min=?,end_min=?,
			date_from=?,date_to=?,target_kind=?,target_id=?,effect=?,effect_data=?,updated_at=? WHERE id=?`,
		s.Name, s.Description, boolInt(s.Enabled), s.TZ, s.DaysMask, s.StartMin, s.EndMin,
		s.DateFrom, s.DateTo, s.TargetKind, s.TargetID, s.Effect,
		schedules.EncodeListIDs(s.ListIDs), nowUTC(), s.ID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteSchedule removes a schedule.
func (db *DB) DeleteSchedule(ctx context.Context, id int64) error {
	res, err := db.SQL.ExecContext(ctx, `DELETE FROM schedules WHERE id=?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// ---------- Local DNS records ----------

const recCols = `id,name,type,value,ttl,enabled,comment,created_at,updated_at`

func scanRec(row interface{ Scan(...any) error }) (*localdns.Record, error) {
	var r localdns.Record
	var en int
	err := row.Scan(&r.ID, &r.Name, &r.Type, &r.Value, &r.TTL, &en,
		&r.Comment, &r.CreatedAt, &r.UpdatedAt)
	r.Enabled = en != 0
	return &r, err
}

// ListLocalRecords returns all records.
func (db *DB) ListLocalRecords(ctx context.Context) ([]localdns.Record, error) {
	rows, err := db.SQL.QueryContext(ctx,
		`SELECT `+recCols+` FROM local_dns_records ORDER BY name, type`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []localdns.Record{}
	for rows.Next() {
		r, err := scanRec(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *r)
	}
	return out, rows.Err()
}

// AddLocalRecord inserts a record.
func (db *DB) AddLocalRecord(ctx context.Context, r *localdns.Record) error {
	res, err := db.SQL.ExecContext(ctx,
		`INSERT INTO local_dns_records(name,type,value,ttl,enabled,comment,created_at,updated_at)
		 VALUES(?,?,?,?,?,?,?,?)`,
		r.Name, r.Type, r.Value, r.TTL, boolInt(r.Enabled), r.Comment, nowUTC(), nowUTC())
	if err != nil {
		return err
	}
	r.ID, _ = res.LastInsertId()
	return nil
}

// UpdateLocalRecord patches a record.
func (db *DB) UpdateLocalRecord(ctx context.Context, r *localdns.Record) error {
	res, err := db.SQL.ExecContext(ctx,
		`UPDATE local_dns_records SET name=?,type=?,value=?,ttl=?,enabled=?,comment=?,updated_at=? WHERE id=?`,
		r.Name, r.Type, r.Value, r.TTL, boolInt(r.Enabled), r.Comment, nowUTC(), r.ID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteLocalRecord removes a record.
func (db *DB) DeleteLocalRecord(ctx context.Context, id int64) error {
	res, err := db.SQL.ExecContext(ctx, `DELETE FROM local_dns_records WHERE id=?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// ---------- Discovery events ----------

// DiscoveryEvent is a recorded observation (new IP, hostname change, ...).
type DiscoveryEvent struct {
	ID        int64  `json:"id"`
	Kind      string `json:"kind"`
	Value     string `json:"value"`
	Detail    string `json:"detail"`
	FirstSeen string `json:"first_seen"`
	LastSeen  string `json:"last_seen"`
	Count     int64  `json:"count"`
	Notified  bool   `json:"notified"`
}

// RecordDiscovery upserts an event; returns true when the row is new.
func (db *DB) RecordDiscovery(ctx context.Context, kind, value, detail string) (bool, error) {
	res, err := db.SQL.ExecContext(ctx,
		`INSERT INTO discovery_events(kind,value,detail,first_seen,last_seen,count,notified)
		 VALUES(?,?,?,?,?,1,0)
		 ON CONFLICT(kind,value) DO UPDATE SET
		   last_seen=excluded.last_seen, detail=excluded.detail, count=discovery_events.count+1`,
		kind, value, detail, nowUTC(), nowUTC())
	if err != nil {
		return false, err
	}
	// sqlite reports changes>1 for the update path via our +1? No — detect
	// newness by whether the row existed before the upsert.
	_ = res
	var n int64
	err = db.SQL.QueryRowContext(ctx,
		`SELECT count FROM discovery_events WHERE kind=? AND value=?`, kind, value).Scan(&n)
	return n <= 1, err
}

// ListDiscoveryEvents returns events, newest activity first.
func (db *DB) ListDiscoveryEvents(ctx context.Context, limit int) ([]DiscoveryEvent, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := db.SQL.QueryContext(ctx,
		`SELECT id,kind,value,detail,first_seen,last_seen,count,notified
		 FROM discovery_events ORDER BY last_seen DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []DiscoveryEvent{}
	for rows.Next() {
		var e DiscoveryEvent
		var n int
		if err := rows.Scan(&e.ID, &e.Kind, &e.Value, &e.Detail, &e.FirstSeen, &e.LastSeen, &e.Count, &n); err != nil {
			return nil, err
		}
		e.Notified = n != 0
		out = append(out, e)
	}
	return out, rows.Err()
}

// AckDiscoveryEvent marks an event notified.
func (db *DB) AckDiscoveryEvent(ctx context.Context, id int64) error {
	res, err := db.SQL.ExecContext(ctx,
		`UPDATE discovery_events SET notified=1 WHERE id=?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// ---------- Upstream health history ----------

// RecordUpstreamHealth appends one probe result per upstream.
func (db *DB) RecordUpstreamHealth(ctx context.Context, upstreamID int64, ok bool, rtt float64, errStr string) error {
	_, err := db.SQL.ExecContext(ctx,
		`INSERT INTO upstream_health(upstream_id,ts,ok,rtt_ms,error) VALUES(?,?,?,?,?)`,
		upstreamID, nowUTC(), boolInt(ok), rtt, errStr)
	return err
}

// UpstreamHealthPoint is one probe.
type UpstreamHealthPoint struct {
	TS    string  `json:"ts"`
	OK    bool    `json:"ok"`
	RTTms float64 `json:"rtt_ms"`
	Error string  `json:"error,omitempty"`
}

// UpstreamHealthHistory returns recent probes for an upstream.
func (db *DB) UpstreamHealthHistory(ctx context.Context, upstreamID int64, limit int) ([]UpstreamHealthPoint, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	rows, err := db.SQL.QueryContext(ctx,
		`SELECT ts,ok,rtt_ms,error FROM upstream_health WHERE upstream_id=? ORDER BY id DESC LIMIT ?`,
		upstreamID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []UpstreamHealthPoint{}
	for rows.Next() {
		var p UpstreamHealthPoint
		var ok int
		if err := rows.Scan(&p.TS, &ok, &p.RTTms, &p.Error); err != nil {
			return nil, err
		}
		p.OK = ok != 0
		out = append(out, p)
	}
	return out, rows.Err()
}

// ---------- Blocklist refresh history ----------

// BlocklistHistoryEntry is one refresh outcome.
type BlocklistHistoryEntry struct {
	ID         int64  `json:"id"`
	TS         string `json:"ts"`
	Status     string `json:"status"` // ok | unchanged | failed
	RuleCount  int64  `json:"rule_count"`
	Bytes      int64  `json:"bytes"`
	Malformed  int64  `json:"malformed"`
	Duplicates int64  `json:"duplicates"`
	Hash       string `json:"hash"`
	Error      string `json:"error,omitempty"`
}

// RecordBlocklistHistory appends a refresh outcome.
func (db *DB) RecordBlocklistHistory(ctx context.Context, listID int64, e BlocklistHistoryEntry) error {
	_, err := db.SQL.ExecContext(ctx,
		`INSERT INTO blocklist_history(blocklist_id,ts,status,rule_count,bytes,malformed,duplicates,hash,error)
		 VALUES(?,?,?,?,?,?,?,?,?)`,
		listID, nowUTC(), e.Status, e.RuleCount, e.Bytes, e.Malformed, e.Duplicates, e.Hash, e.Error)
	return err
}

// BlocklistHistory returns refresh history, newest first.
func (db *DB) BlocklistHistory(ctx context.Context, listID int64, limit int) ([]BlocklistHistoryEntry, error) {
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	rows, err := db.SQL.QueryContext(ctx,
		`SELECT id,ts,status,rule_count,bytes,malformed,duplicates,hash,error
		 FROM blocklist_history WHERE blocklist_id=? ORDER BY id DESC LIMIT ?`, listID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []BlocklistHistoryEntry{}
	for rows.Next() {
		var e BlocklistHistoryEntry
		if err := rows.Scan(&e.ID, &e.TS, &e.Status, &e.RuleCount, &e.Bytes,
			&e.Malformed, &e.Duplicates, &e.Hash, &e.Error); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// ---------- Enforcement operations ----------

// EnforcementOp is a recorded preview/apply/rollback on a target system.
type EnforcementOp struct {
	ID          int64  `json:"id"`
	TS          string `json:"ts"`
	Integration string `json:"integration"`
	Action      string `json:"action"`
	Status      string `json:"status"`
	Preview     string `json:"preview"`
	Result      string `json:"result"`
	Actor       string `json:"actor"`
}

// RecordEnforcementOp persists an operation row.
func (db *DB) RecordEnforcementOp(ctx context.Context, op *EnforcementOp) error {
	res, err := db.SQL.ExecContext(ctx,
		`INSERT INTO enforcement_operations(ts,integration,action,status,preview,result,actor)
		 VALUES(?,?,?,?,?,?,?)`,
		nowUTC(), op.Integration, op.Action, op.Status, op.Preview, op.Result, op.Actor)
	if err != nil {
		return err
	}
	op.ID, _ = res.LastInsertId()
	return nil
}

// UpdateEnforcementOpStatus patches status/result.
func (db *DB) UpdateEnforcementOpStatus(ctx context.Context, id int64, status, result string) error {
	_, err := db.SQL.ExecContext(ctx,
		`UPDATE enforcement_operations SET status=?, result=? WHERE id=?`, status, result, id)
	return err
}

// ListEnforcementOps returns recent operations.
func (db *DB) ListEnforcementOps(ctx context.Context, limit int) ([]EnforcementOp, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := db.SQL.QueryContext(ctx,
		`SELECT id,ts,integration,action,status,preview,result,actor
		 FROM enforcement_operations ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []EnforcementOp{}
	for rows.Next() {
		var op EnforcementOp
		if err := rows.Scan(&op.ID, &op.TS, &op.Integration, &op.Action,
			&op.Status, &op.Preview, &op.Result, &op.Actor); err != nil {
			return nil, err
		}
		out = append(out, op)
	}
	return out, rows.Err()
}

// SaveEnforcementBackup stores a rollback blob for an operation.
func (db *DB) SaveEnforcementBackup(ctx context.Context, opID int64, content string) error {
	_, err := db.SQL.ExecContext(ctx,
		`INSERT INTO enforcement_backups(operation_id,ts,content) VALUES(?,?,?)`,
		opID, nowUTC(), content)
	return err
}

// EnforcementBackup returns the latest backup for an operation.
func (db *DB) EnforcementBackup(ctx context.Context, opID int64) (string, error) {
	var content string
	err := db.SQL.QueryRowContext(ctx,
		`SELECT content FROM enforcement_backups WHERE operation_id=? ORDER BY id DESC LIMIT 1`,
		opID).Scan(&content)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return content, err
}

// ---------- Client identities ----------

// Identity is a secondary identifier bound to a client (mac, hostname...).
type Identity struct {
	ID        int64  `json:"id"`
	ClientID  int64  `json:"client_id"`
	Kind      string `json:"kind"`
	Value     string `json:"value"`
	CreatedAt string `json:"created_at"`
}

// ListIdentities returns identities; clientID 0 lists all.
func (db *DB) ListIdentities(ctx context.Context, clientID int64) ([]Identity, error) {
	q := `SELECT id,client_id,kind,value,created_at FROM client_identities`
	args := []any{}
	if clientID != 0 {
		q += ` WHERE client_id=?`
		args = append(args, clientID)
	}
	rows, err := db.SQL.QueryContext(ctx, q+` ORDER BY id`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Identity{}
	for rows.Next() {
		var i Identity
		if err := rows.Scan(&i.ID, &i.ClientID, &i.Kind, &i.Value, &i.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, i)
	}
	return out, rows.Err()
}

// BindIdentity links an identifier to a client.
func (db *DB) BindIdentity(ctx context.Context, clientID int64, kind, value string) error {
	_, err := db.SQL.ExecContext(ctx,
		`INSERT INTO client_identities(client_id,kind,value,created_at) VALUES(?,?,?,?)`,
		clientID, kind, value, nowUTC())
	if isUniqueErr(err) {
		return ErrDuplicate
	}
	return err
}

// UnbindIdentity removes an identity row.
func (db *DB) UnbindIdentity(ctx context.Context, id int64) error {
	res, err := db.SQL.ExecContext(ctx, `DELETE FROM client_identities WHERE id=?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// ClientIDByIdentity resolves a bound identifier to its client.
func (db *DB) ClientIDByIdentity(ctx context.Context, kind, value string) (int64, error) {
	var id int64
	err := db.SQL.QueryRowContext(ctx,
		`SELECT client_id FROM client_identities WHERE kind=? AND value=?`, kind, value).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	return id, err
}

// ---------- Extended audit ----------

// AuditEntry is a structured audit row.
type AuditEntry struct {
	ID       int64  `json:"id"`
	TS       string `json:"ts"`
	Actor    string `json:"actor"`
	Action   string `json:"action"`
	Resource string `json:"resource"`
	Detail   string `json:"detail"`
	Result   string `json:"result"`
}

// AuditEx writes a structured audit event.
func (db *DB) AuditEx(ctx context.Context, actor, action, resource, detail, result string) {
	if result == "" {
		result = "ok"
	}
	_, _ = db.SQL.ExecContext(ctx,
		`INSERT INTO audit(ts,actor,action,resource,detail,result) VALUES(?,?,?,?,?,?)`,
		nowUTC(), actor, action, resource, detail, result)
}

// AuditFilter selects audit rows.
type AuditFilter struct {
	Action string
	Actor  string
	Since  time.Time
	Limit  int
	Offset int
}

// ListAuditFiltered returns rows plus total for pagination.
func (db *DB) ListAuditFiltered(ctx context.Context, f AuditFilter) ([]AuditEntry, int64, error) {
	var where []string
	var args []any
	if f.Action != "" {
		where = append(where, `action LIKE ?`)
		args = append(args, "%"+f.Action+"%")
	}
	if f.Actor != "" {
		where = append(where, `actor = ?`)
		args = append(args, f.Actor)
	}
	if !f.Since.IsZero() {
		where = append(where, `ts >= ?`)
		args = append(args, f.Since.UTC().Format(time.RFC3339))
	}
	w := ""
	if len(where) > 0 {
		w = " WHERE " + joinAnd(where)
	}
	var total int64
	if err := db.SQL.QueryRowContext(ctx, `SELECT COUNT(*) FROM audit`+w, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	limit := f.Limit
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := db.SQL.QueryContext(ctx,
		`SELECT id,ts,actor,action,resource,detail,result FROM audit`+w+
			` ORDER BY id DESC LIMIT ? OFFSET ?`, append(args, limit, f.Offset)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []AuditEntry{}
	for rows.Next() {
		var e AuditEntry
		if err := rows.Scan(&e.ID, &e.TS, &e.Actor, &e.Action, &e.Resource, &e.Detail, &e.Result); err != nil {
			return nil, 0, err
		}
		out = append(out, e)
	}
	return out, total, rows.Err()
}

// DeleteAuditBefore removes audit rows older than cutoff.
func (db *DB) DeleteAuditBefore(ctx context.Context, cutoff time.Time) (int64, error) {
	res, err := db.SQL.ExecContext(ctx,
		`DELETE FROM audit WHERE ts < ?`, cutoff.UTC().Format(time.RFC3339))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// PruneUpstreamHealth keeps at most keep newest probe rows.
func (db *DB) PruneUpstreamHealth(ctx context.Context, keep int64) error {
	_, err := db.SQL.ExecContext(ctx,
		`DELETE FROM upstream_health WHERE id NOT IN
		 (SELECT id FROM upstream_health ORDER BY id DESC LIMIT ?)`, keep)
	return err
}

// SetClientIdentitySource updates the provenance label for a client.
func (db *DB) SetClientIdentitySource(ctx context.Context, id int64, source string) error {
	_, err := db.SQL.ExecContext(ctx,
		`UPDATE clients SET identity_source=? WHERE id=?`, source, id)
	return err
}

// SetClientClassification sets a client's device class.
func (db *DB) SetClientClassification(ctx context.Context, id int64, cls string) error {
	_, err := db.SQL.ExecContext(ctx,
		`UPDATE clients SET classification=? WHERE id=?`, cls, id)
	return err
}

func joinAnd(parts []string) string {
	out := parts[0]
	for _, p := range parts[1:] {
		out += " AND " + p
	}
	return out
}

func splitCSV(s string) []string {
	var out []string
	cur := ""
	for _, c := range s {
		if c == ',' {
			if cur != "" {
				out = append(out, cur)
			}
			cur = ""
		} else {
			cur += string(c)
		}
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}
