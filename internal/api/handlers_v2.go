package api

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/w0wzahh/blacknet/internal/blocklists"
	"github.com/w0wzahh/blacknet/internal/database"
	"github.com/w0wzahh/blacknet/internal/discovery"
	"github.com/w0wzahh/blacknet/internal/enforcement"
	"github.com/w0wzahh/blacknet/internal/filtering"
	"github.com/w0wzahh/blacknet/internal/localdns"
	"github.com/w0wzahh/blacknet/internal/policies"
	"github.com/w0wzahh/blacknet/internal/schedules"
)

// ---------- policy groups ----------

func (s *Server) hGroups(w http.ResponseWriter, r *http.Request) {
	items, err := s.d.DB.ListGroups(r.Context())
	if err != nil {
		jerr(w, 500, err.Error())
		return
	}
	j(w, 200, items)
}

func (s *Server) hGroupCreate(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		Enabled     *bool  `json:"enabled"`
		UpstreamID  int64  `json:"upstream_id"`
	}
	if !decode(w, r, &body) {
		return
	}
	g := policies.Group{
		Name:        body.Name,
		Description: body.Description,
		Enabled:     body.Enabled == nil || *body.Enabled,
		UpstreamID:  body.UpstreamID,
	}
	if errs := g.Validate(); len(errs) > 0 {
		jerrFields(w, 400, "validation failed", errs)
		return
	}
	if g.UpstreamID != 0 {
		if !s.upstreamExists(r.Context(), g.UpstreamID) {
			jerr(w, 400, "unknown upstream_id")
			return
		}
	}
	if err := s.d.DB.CreateGroup(r.Context(), &g); err != nil {
		if errors.Is(err, database.ErrDuplicate) {
			jerr(w, 409, "a group with this name already exists")
			return
		}
		jerr(w, 500, err.Error())
		return
	}
	_ = s.d.App.ReloadPolicies(r.Context())
	s.d.DB.AuditEx(r.Context(), "admin", "group.create", fmt.Sprintf("group:%d", g.ID), g.Name, "ok")
	j(w, 201, g)
}

func (s *Server) hGroupPatch(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	cur, err := s.d.DB.GetGroup(r.Context(), id)
	if errors.Is(err, database.ErrNotFound) {
		jerr(w, 404, "group not found")
		return
	}
	if err != nil {
		jerr(w, 500, err.Error())
		return
	}
	var body struct {
		Name        *string `json:"name"`
		Description *string `json:"description"`
		Enabled     *bool   `json:"enabled"`
		UpstreamID  *int64  `json:"upstream_id"`
	}
	if !decode(w, r, &body) {
		return
	}
	g := *cur
	if body.Name != nil {
		g.Name = *body.Name
	}
	if body.Description != nil {
		g.Description = *body.Description
	}
	if body.Enabled != nil {
		g.Enabled = *body.Enabled
	}
	if body.UpstreamID != nil {
		if *body.UpstreamID != 0 && !s.upstreamExists(r.Context(), *body.UpstreamID) {
			jerr(w, 400, "unknown upstream_id")
			return
		}
		g.UpstreamID = *body.UpstreamID
	}
	if errs := g.Validate(); len(errs) > 0 {
		jerrFields(w, 400, "validation failed", errs)
		return
	}
	if err := s.d.DB.UpdateGroup(r.Context(), &g); err != nil {
		if errors.Is(err, database.ErrDuplicate) {
			jerr(w, 409, "a group with this name already exists")
			return
		}
		jerr(w, 500, err.Error())
		return
	}
	_ = s.d.App.ReloadPolicies(r.Context())
	s.d.DB.AuditEx(r.Context(), "admin", "group.update", fmt.Sprintf("group:%d", id), g.Name, "ok")
	j(w, 200, g)
}

func (s *Server) hGroupDelete(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if r.URL.Query().Get("confirm") != "true" {
		jerr(w, 400, "pass confirm=true — members revert to the default policy")
		return
	}
	if err := s.d.DB.DeleteGroup(r.Context(), id); err != nil {
		if errors.Is(err, database.ErrNotFound) {
			jerr(w, 404, "group not found")
			return
		}
		jerr(w, 500, err.Error())
		return
	}
	_ = s.d.App.ReloadPolicies(r.Context())
	s.d.DB.AuditEx(r.Context(), "admin", "group.delete", fmt.Sprintf("group:%d", id), "", "ok")
	j(w, 200, map[string]any{"ok": true})
}

// hGroupDuplicate copies a group including its blocklist assignments.
func (s *Server) hGroupDuplicate(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	cur, err := s.d.DB.GetGroup(r.Context(), id)
	if err != nil {
		jerr(w, 404, "group not found")
		return
	}
	groups, _ := s.d.DB.ListGroups(r.Context())
	var srcLists []int64
	for _, g := range groups {
		if g.ID == id {
			srcLists = g.ListIDs
		}
	}
	dup := *cur
	dup.ID = 0
	dup.Name = uniqueName(cur.Name+" copy", groups)
	if err := s.d.DB.CreateGroup(r.Context(), &dup); err != nil {
		jerr(w, 500, err.Error())
		return
	}
	if len(srcLists) > 0 {
		_ = s.d.DB.SetBlocklistGroups(r.Context(), 0, nil) // no-op safety
		for _, lid := range srcLists {
			lgm, _ := s.d.DB.ListGroupMap(r.Context())
			lgm[lid] = append(append([]int64(nil), lgm[lid]...), dup.ID)
			_ = s.d.DB.SetBlocklistGroups(r.Context(), lid, lgm[lid])
		}
	}
	_ = s.d.App.ReloadPolicies(r.Context())
	s.d.DB.AuditEx(r.Context(), "admin", "group.duplicate", fmt.Sprintf("group:%d", dup.ID), "from "+cur.Name, "ok")
	j(w, 201, dup)
}

func uniqueName(base string, groups []policies.Group) string {
	names := map[string]bool{}
	for _, g := range groups {
		names[g.Name] = true
	}
	if !names[base] {
		return base
	}
	for i := 2; ; i++ {
		cand := fmt.Sprintf("%s %d", base, i)
		if !names[cand] {
			return cand
		}
	}
}

func (s *Server) upstreamExists(ctx context.Context, id int64) bool {
	ups, err := s.d.DB.ListUpstreams(ctx)
	if err != nil {
		return false
	}
	for _, u := range ups {
		if u.ID == id {
			return true
		}
	}
	return false
}

// ---------- assignments ----------

func (s *Server) hAssignments(w http.ResponseWriter, r *http.Request) {
	items, err := s.d.DB.ListAssignments(r.Context())
	if err != nil {
		jerr(w, 500, err.Error())
		return
	}
	j(w, 200, items)
}

func (s *Server) hAssignmentCreate(w http.ResponseWriter, r *http.Request) {
	var a policies.Assignment
	if !decode(w, r, &a) {
		return
	}
	a.ID = 0
	if errs := a.Validate(); len(errs) > 0 {
		jerrFields(w, 400, "validation failed", errs)
		return
	}
	if _, err := s.d.DB.GetGroup(r.Context(), a.GroupID); err != nil {
		jerr(w, 400, "unknown group_id")
		return
	}
	if err := s.d.DB.AddAssignment(r.Context(), &a); err != nil {
		if errors.Is(err, database.ErrDuplicate) {
			jerr(w, 409, "an assignment for this target already exists")
			return
		}
		jerr(w, 500, err.Error())
		return
	}
	_ = s.d.App.ReloadPolicies(r.Context())
	s.d.DB.AuditEx(r.Context(), "admin", "assignment.create", fmt.Sprintf("assignment:%d", a.ID), a.Describe(), "ok")
	j(w, 201, a)
}

func (s *Server) hAssignmentDelete(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if err := s.d.DB.DeleteAssignment(r.Context(), id); err != nil {
		if errors.Is(err, database.ErrNotFound) {
			jerr(w, 404, "assignment not found")
			return
		}
		jerr(w, 500, err.Error())
		return
	}
	_ = s.d.App.ReloadPolicies(r.Context())
	s.d.DB.AuditEx(r.Context(), "admin", "assignment.delete", fmt.Sprintf("assignment:%d", id), "", "ok")
	j(w, 200, map[string]any{"ok": true})
}

// hPolicySimulate is the "would this domain be blocked" tool — same resolver
// and engine path as live traffic, plus optional hypothetical subject.
func (s *Server) hPolicySimulate(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Domain   string `json:"domain"`
		ClientID int64  `json:"client_id"`
		ClientIP string `json:"client_ip"`
		GroupID  *int64 `json:"group_id"`
		At       string `json:"at"` // RFC3339, evaluates schedules at a different time
	}
	if !decode(w, r, &body) {
		return
	}
	d := filtering.Normalize(body.Domain)
	if d == "" {
		jerr(w, 400, "domain required")
		return
	}
	var sub filtering.Subject
	if body.ClientIP != "" {
		ip, err := parseIP(body.ClientIP)
		if err != nil {
			jerr(w, 400, "invalid client_ip")
			return
		}
		cid := s.d.QLog.LookupClient(ip)
		sub = filtering.Subject{ClientID: cid,
			GroupID: s.d.App.PolicyResolver().GroupFor(ip, cid)}
	} else {
		sub = s.testSubject(r.Context(), body.ClientID, body.GroupID)
	}
	if body.At != "" {
		t, err := time.Parse(time.RFC3339, body.At)
		if err != nil {
			jerr(w, 400, "at must be RFC3339")
			return
		}
		sub.Now = t
	}
	j(w, 200, s.d.Engine.Explain(d, sub))
}

// ---------- rule intelligence ----------

// hRuleInspect explains how a domain resolves for a subject: decision trace,
// every matching rule, and which lists contain the domain.
func (s *Server) hRuleInspect(w http.ResponseWriter, r *http.Request) {
	d := filtering.Normalize(r.URL.Query().Get("domain"))
	if d == "" {
		jerr(w, 400, "domain required")
		return
	}
	var clientID, groupID int64
	if v := r.URL.Query().Get("client_id"); v != "" {
		clientID, _ = strconv.ParseInt(v, 10, 64)
	}
	var groupPtr *int64
	if v := r.URL.Query().Get("group_id"); v != "" {
		groupID, _ = strconv.ParseInt(v, 10, 64)
		groupPtr = &groupID
	}
	sub := s.testSubject(r.Context(), clientID, groupPtr)
	ex := s.d.Engine.Explain(d, sub)
	rules := s.d.Engine.MatchAll(d, sub)
	blocks, allows := s.d.Engine.DomainSources(d)
	// Resolve list ids to names for the UI.
	names := map[int64]string{}
	if lists, err := s.d.DB.ListBlocklists(r.Context()); err == nil {
		for _, l := range lists {
			names[l.ID] = l.Name
		}
	}
	srcList := func(m map[int64]string) []map[string]any {
		out := []map[string]any{}
		for id, suffix := range m {
			out = append(out, map[string]any{
				"list_id": id, "name": names[id], "matched_domain": suffix,
			})
		}
		return out
	}
	j(w, 200, map[string]any{
		"domain":        d,
		"subject":       sub,
		"explanation":   ex,
		"matched_rules": rules,
		"in_blocklists": srcList(blocks),
		"exceptions":    srcList(allows),
	})
}

// hRuleBatchTest evaluates many domains at once for the same subject.
func (s *Server) hRuleBatchTest(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Domains  []string `json:"domains"`
		Text     string   `json:"text"` // alternative: newline/paste input
		ClientID int64    `json:"client_id"`
		GroupID  *int64   `json:"group_id"`
	}
	if !decode(w, r, &body) {
		return
	}
	domains := append([]string(nil), body.Domains...)
	if body.Text != "" {
		for _, line := range strings.Split(body.Text, "\n") {
			if d := filtering.Normalize(strings.TrimSpace(line)); d != "" {
				domains = append(domains, d)
			}
		}
	}
	if len(domains) == 0 {
		jerr(w, 400, "provide domains or text")
		return
	}
	if len(domains) > 1000 {
		jerr(w, 400, "max 1000 domains per batch")
		return
	}
	sub := s.testSubject(r.Context(), body.ClientID, body.GroupID)
	type item struct {
		Domain  string           `json:"domain"`
		Blocked bool             `json:"blocked"`
		Reason  string           `json:"reason"`
		Trace   []filtering.Step `json:"trace"`
	}
	out := make([]item, 0, len(domains))
	for _, d := range domains {
		ex := s.d.Engine.Explain(d, sub)
		out = append(out, item{Domain: d, Blocked: ex.Decision.Blocked,
			Reason: string(ex.Decision.Reason), Trace: ex.Steps})
	}
	j(w, 200, map[string]any{"subject": sub, "results": out})
}

// hRuleConflicts reports overlaps for a candidate rule (or lists all current
// conflicts when no candidate is given).
func (s *Server) hRuleConflicts(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	domain := filtering.Normalize(q.Get("domain"))
	action := q.Get("action") // allow|block|""
	scope := q.Get("scope")   // exact|tree|""
	clientID, _ := strconv.ParseInt(q.Get("client_id"), 10, 64)
	groupID, _ := strconv.ParseInt(q.Get("group_id"), 10, 64)

	rules, err := s.d.DB.ListRules(r.Context())
	if err != nil {
		jerr(w, 500, err.Error())
		return
	}
	type conflict struct {
		RuleID   int64  `json:"rule_id"`
		Domain   string `json:"domain"`
		Relation string `json:"relation"` // conflict|shadowed|redundant|covers
		Detail   string `json:"detail"`
	}
	out := []conflict{}
	scopeOf := func(ru filtering.Rule) string { return ru.ScopeName() }

	if domain != "" {
		// Candidate-mode: find rules interacting with this domain.
		cand := filtering.Rule{Domain: domain, Action: filtering.Action(action),
			Scope: filtering.Scope(scope), ClientID: clientID, GroupID: groupID, Enabled: true}
		for _, ru := range rules {
			if !ru.Enabled {
				continue
			}
			rel := relate(cand, ru)
			if rel == "" {
				continue
			}
			out = append(out, conflict{RuleID: ru.ID, Domain: ru.Domain, Relation: rel,
				Detail: fmt.Sprintf("%s %s rule at %s scope (%s action)", scopeOf(ru), ru.Scope, ru.Domain, ru.Action)})
		}
		j(w, 200, out)
		return
	}

	// Global scan: pairwise conflicts among enabled rules.
	for i := 0; i < len(rules); i++ {
		for k := i + 1; k < len(rules); k++ {
			a, b := rules[i], rules[k]
			if !a.Enabled || !b.Enabled {
				continue
			}
			rel := relate(a, b)
			if rel == "" {
				continue
			}
			out = append(out, conflict{RuleID: b.ID, Domain: b.Domain, Relation: rel,
				Detail: fmt.Sprintf("vs %s %s rule #%d at %s scope", a.Scope, a.Domain, a.ID, scopeOf(a))})
		}
	}
	j(w, 200, out)
}

// relate reports how rule a (candidate/new) interacts with existing rule b.
func relate(a, b filtering.Rule) string {
	// Same scope tier only compares same tier; cross-tier rules both apply
	// (higher tier wins — not a conflict, just precedence).
	sameTier := a.ClientID == b.ClientID && a.GroupID == b.GroupID
	samePattern := a.Domain == b.Domain && a.Scope == b.Scope
	switch {
	case samePattern && sameTier:
		if a.Action == b.Action {
			return "redundant"
		}
		return "conflict"
	case samePattern && !sameTier:
		return "shadowed" // different tier: same pattern, precedence decides
	}
	// Tree overlaps.
	if a.Scope == filtering.ScopeTree && filtering.IsSubdomainOf(a.Domain, b.Domain) && b.Scope == filtering.ScopeTree {
		if a.Action != b.Action {
			return "conflict"
		}
		return "covered-by"
	}
	if b.Scope == filtering.ScopeTree && filtering.IsSubdomainOf(b.Domain, a.Domain) {
		if a.Scope == filtering.ScopeExact || a.Scope == filtering.ScopeTree {
			if a.Action != b.Action {
				return "conflict"
			}
			return "covers"
		}
	}
	if a.Scope == filtering.ScopeExact && b.Scope == filtering.ScopeTree && filtering.IsSubdomainOf(a.Domain, b.Domain) {
		if a.Action != b.Action {
			return "conflict"
		}
		return "covered-by"
	}
	return ""
}

// ---------- schedules ----------

func (s *Server) hSchedules(w http.ResponseWriter, r *http.Request) {
	items, err := s.d.DB.ListSchedules(r.Context())
	if err != nil {
		jerr(w, 500, err.Error())
		return
	}
	now := time.Now()
	type row struct {
		schedules.Schedule
		ActiveNow bool                  `json:"active_now"`
		Next      *schedules.Transition `json:"next_transition,omitempty"`
	}
	out := make([]row, 0, len(items))
	for i := range items {
		it := row{Schedule: items[i], ActiveNow: items[i].Active(now)}
		if tr, ok := items[i].NextTransition(now); ok {
			it.Next = &tr
		}
		out = append(out, it)
	}
	j(w, 200, out)
}

func (s *Server) hScheduleCreate(w http.ResponseWriter, r *http.Request) {
	var body struct {
		schedules.Schedule
		Enabled *bool `json:"enabled"`
	}
	if !decode(w, r, &body) {
		return
	}
	sc := body.Schedule
	sc.ID = 0
	// Created enabled unless the caller explicitly says otherwise.
	sc.Enabled = body.Enabled == nil || *body.Enabled
	if sc.TZ == "" {
		sc.TZ = "UTC"
	}

	if errs := sc.Validate(); len(errs) > 0 {
		jerrFields(w, 400, "validation failed", errs)
		return
	}
	if err := s.checkScheduleTarget(r.Context(), &sc); err != nil {
		jerr(w, 400, err.Error())
		return
	}
	if err := s.d.DB.CreateSchedule(r.Context(), &sc); err != nil {
		jerr(w, 500, err.Error())
		return
	}
	_ = s.d.App.ReloadRules(r.Context())
	s.d.DB.AuditEx(r.Context(), "admin", "schedule.create", fmt.Sprintf("schedule:%d", sc.ID), sc.Name, "ok")
	j(w, 201, sc)
}

func (s *Server) checkScheduleTarget(ctx context.Context, sc *schedules.Schedule) error {
	switch sc.TargetKind {
	case schedules.TargetGroup:
		if _, err := s.d.DB.GetGroup(ctx, sc.TargetID); err != nil {
			return fmt.Errorf("target group does not exist")
		}
	case schedules.TargetClient:
		if _, err := s.d.DB.GetClient(ctx, sc.TargetID); err != nil {
			return fmt.Errorf("target client does not exist")
		}
	}
	return nil
}

func (s *Server) hSchedulePatch(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	cur, err := s.d.DB.GetSchedule(r.Context(), id)
	if errors.Is(err, database.ErrNotFound) {
		jerr(w, 404, "schedule not found")
		return
	}
	if err != nil {
		jerr(w, 500, err.Error())
		return
	}
	var body map[string]json.RawMessage
	if !decode(w, r, &body) {
		return
	}
	sc := *cur
	apply := func(key string, dst any) {
		if raw, ok := body[key]; ok {
			_ = json.Unmarshal(raw, dst)
		}
	}
	apply("name", &sc.Name)
	apply("description", &sc.Description)
	apply("enabled", &sc.Enabled)
	apply("tz", &sc.TZ)
	apply("days_mask", &sc.DaysMask)
	apply("start_min", &sc.StartMin)
	apply("end_min", &sc.EndMin)
	apply("date_from", &sc.DateFrom)
	apply("date_to", &sc.DateTo)
	apply("target_kind", &sc.TargetKind)
	apply("target_id", &sc.TargetID)
	apply("effect", &sc.Effect)
	apply("list_ids", &sc.ListIDs)
	if errs := sc.Validate(); len(errs) > 0 {
		jerrFields(w, 400, "validation failed", errs)
		return
	}
	if err := s.checkScheduleTarget(r.Context(), &sc); err != nil {
		jerr(w, 400, err.Error())
		return
	}
	if err := s.d.DB.UpdateSchedule(r.Context(), &sc); err != nil {
		jerr(w, 500, err.Error())
		return
	}
	_ = s.d.App.ReloadRules(r.Context())
	s.d.DB.AuditEx(r.Context(), "admin", "schedule.update", fmt.Sprintf("schedule:%d", id), sc.Name, "ok")
	j(w, 200, sc)
}

func (s *Server) hScheduleDelete(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if err := s.d.DB.DeleteSchedule(r.Context(), id); err != nil {
		if errors.Is(err, database.ErrNotFound) {
			jerr(w, 404, "schedule not found")
			return
		}
		jerr(w, 500, err.Error())
		return
	}
	_ = s.d.App.ReloadRules(r.Context())
	s.d.DB.AuditEx(r.Context(), "admin", "schedule.delete", fmt.Sprintf("schedule:%d", id), "", "ok")
	j(w, 200, map[string]any{"ok": true})
}

// hSchedulePreview returns whether the schedule is active at `at` plus the
// next two transitions — the UI shows this as "what happens when".
func (s *Server) hSchedulePreview(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	sc, err := s.d.DB.GetSchedule(r.Context(), id)
	if err != nil {
		jerr(w, 404, "schedule not found")
		return
	}
	at := time.Now()
	if v := r.URL.Query().Get("at"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			at = t
		}
	}
	transitions := []schedules.Transition{}
	cur := at
	for i := 0; i < 3; i++ {
		tr, ok := sc.NextTransition(cur)
		if !ok {
			break
		}
		transitions = append(transitions, tr)
		cur = tr.At.Add(time.Minute)
	}
	j(w, 200, map[string]any{
		"schedule": sc, "at": at.UTC().Format(time.RFC3339),
		"active": sc.Active(at), "transitions": transitions,
	})
}

// ---------- local DNS ----------

func (s *Server) hLocalRecords(w http.ResponseWriter, r *http.Request) {
	items, err := s.d.DB.ListLocalRecords(r.Context())
	if err != nil {
		jerr(w, 500, err.Error())
		return
	}
	j(w, 200, items)
}

func (s *Server) hLocalRecordCreate(w http.ResponseWriter, r *http.Request) {
	var body struct {
		localdns.Record
		Enabled *bool `json:"enabled"`
	}
	if !decode(w, r, &body) {
		return
	}
	rec := body.Record
	rec.ID = 0
	rec.Enabled = body.Enabled == nil || *body.Enabled
	if rec.TTL == 0 {
		rec.TTL = 300
	}
	errs, warnings := rec.Validate()
	if len(errs) > 0 {
		jerrFields(w, 400, "validation failed", errs)
		return
	}
	existing, _ := s.d.DB.ListLocalRecords(r.Context())
	warnings = append(warnings, localdns.Conflicts(existing, &rec)...)
	if err := s.d.DB.AddLocalRecord(r.Context(), &rec); err != nil {
		jerr(w, 500, err.Error())
		return
	}
	_ = s.d.App.ReloadLocal(r.Context())
	s.d.DB.AuditEx(r.Context(), "admin", "localdns.create", fmt.Sprintf("record:%d", rec.ID),
		rec.Name+" "+rec.Type, "ok")
	j(w, 201, map[string]any{"record": rec, "warnings": warnings})
}

func (s *Server) hLocalRecordPatch(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	recs, err := s.d.DB.ListLocalRecords(r.Context())
	if err != nil {
		jerr(w, 500, err.Error())
		return
	}
	var cur *localdns.Record
	for i := range recs {
		if recs[i].ID == id {
			cur = &recs[i]
		}
	}
	if cur == nil {
		jerr(w, 404, "record not found")
		return
	}
	var body struct {
		Name    *string `json:"name"`
		Type    *string `json:"type"`
		Value   *string `json:"value"`
		TTL     *int    `json:"ttl"`
		Enabled *bool   `json:"enabled"`
		Comment *string `json:"comment"`
	}
	if !decode(w, r, &body) {
		return
	}
	rec := *cur
	if body.Name != nil {
		rec.Name = *body.Name
	}
	if body.Type != nil {
		rec.Type = *body.Type
	}
	if body.Value != nil {
		rec.Value = *body.Value
	}
	if body.TTL != nil {
		rec.TTL = *body.TTL
	}
	if body.Enabled != nil {
		rec.Enabled = *body.Enabled
	}
	if body.Comment != nil {
		rec.Comment = *body.Comment
	}
	errs, warnings := rec.Validate()
	if len(errs) > 0 {
		jerrFields(w, 400, "validation failed", errs)
		return
	}
	warnings = append(warnings, localdns.Conflicts(recs, &rec)...)
	if err := s.d.DB.UpdateLocalRecord(r.Context(), &rec); err != nil {
		jerr(w, 500, err.Error())
		return
	}
	_ = s.d.App.ReloadLocal(r.Context())
	s.d.DB.AuditEx(r.Context(), "admin", "localdns.update", fmt.Sprintf("record:%d", id), rec.Name, "ok")
	j(w, 200, map[string]any{"record": rec, "warnings": warnings})
}

func (s *Server) hLocalRecordDelete(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if err := s.d.DB.DeleteLocalRecord(r.Context(), id); err != nil {
		if errors.Is(err, database.ErrNotFound) {
			jerr(w, 404, "record not found")
			return
		}
		jerr(w, 500, err.Error())
		return
	}
	_ = s.d.App.ReloadLocal(r.Context())
	s.d.DB.AuditEx(r.Context(), "admin", "localdns.delete", fmt.Sprintf("record:%d", id), "", "ok")
	j(w, 200, map[string]any{"ok": true})
}

// hLocalRecordTest answers a question against the local store exactly as the
// DNS server would.
func (s *Server) hLocalRecordTest(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name  string `json:"name"`
		QType string `json:"qtype"`
	}
	if !decode(w, r, &body) {
		return
	}
	name := filtering.Normalize(body.Name)
	if name == "" {
		jerr(w, 400, "name required")
		return
	}
	qt := uint16(dns.TypeA)
	if t, ok := dns.StringToType[strings.ToUpper(body.QType)]; ok && body.QType != "" {
		qt = t
	}
	m := s.localStore().Answer(dns.Question{Name: dns.Fqdn(name), Qtype: qt, Qclass: dns.ClassINET})
	if m == nil {
		j(w, 200, map[string]any{"matched": false})
		return
	}
	answers := []string{}
	for _, rr := range m.Answer {
		answers = append(answers, rr.String())
	}
	j(w, 200, map[string]any{
		"matched": true, "rcode": dns.RcodeToString[m.Rcode], "answers": answers,
	})
}

func (s *Server) localStore() *localdns.Store {
	return s.d.App.LocalStore()
}

// ---------- discovery ----------

func (s *Server) hDiscoveryEvents(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	items, err := s.d.DB.ListDiscoveryEvents(r.Context(), limit)
	if err != nil {
		jerr(w, 500, err.Error())
		return
	}
	j(w, 200, map[string]any{
		"items":           items,
		"enabled":         s.d.App.GetSettings().DiscoveryEnabled,
		"host_interfaces": discovery.Interfaces(),
	})
}

func (s *Server) hDiscoveryAck(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if err := s.d.DB.AckDiscoveryEvent(r.Context(), id); err != nil {
		if errors.Is(err, database.ErrNotFound) {
			jerr(w, 404, "event not found")
			return
		}
		jerr(w, 500, err.Error())
		return
	}
	j(w, 200, map[string]any{"ok": true})
}

func (s *Server) hDiscoveryScan(w http.ResponseWriter, r *http.Request) {
	go s.d.App.ScanDiscovery(context.Background())
	s.d.DB.AuditEx(r.Context(), "admin", "discovery.scan", "", "manual scan", "ok")
	j(w, 202, map[string]any{"started": true})
}

func (s *Server) hClientIdentities(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	items, err := s.d.DB.ListIdentities(r.Context(), id)
	if err != nil {
		jerr(w, 500, err.Error())
		return
	}
	j(w, 200, items)
}

func (s *Server) hClientIdentityBind(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var body struct {
		Kind  string `json:"kind"`
		Value string `json:"value"`
	}
	if !decode(w, r, &body) {
		return
	}
	body.Kind = strings.ToLower(strings.TrimSpace(body.Kind))
	body.Value = strings.TrimSpace(body.Value)
	switch body.Kind {
	case "mac", "hostname", "dhcp-fingerprint":
	default:
		jerr(w, 400, "kind must be mac, hostname or dhcp-fingerprint")
		return
	}
	if body.Value == "" {
		jerr(w, 400, "value required")
		return
	}
	if err := s.d.DB.BindIdentity(r.Context(), id, body.Kind, body.Value); err != nil {
		if errors.Is(err, database.ErrDuplicate) {
			jerr(w, 409, "identity already bound (possibly to another client)")
			return
		}
		jerr(w, 500, err.Error())
		return
	}
	s.d.DB.AuditEx(r.Context(), "admin", "identity.bind", fmt.Sprintf("client:%d", id),
		body.Kind+"="+body.Value, "ok")
	j(w, 201, map[string]any{"ok": true})
}

func (s *Server) hClientIdentityUnbind(w http.ResponseWriter, r *http.Request) {
	if _, ok := pathID(w, r); !ok {
		return
	}
	iid, ok2 := pathIDN(w, r, "iid")
	if !ok2 {
		return
	}
	if err := s.d.DB.UnbindIdentity(r.Context(), iid); err != nil {
		if errors.Is(err, database.ErrNotFound) {
			jerr(w, 404, "identity not found")
			return
		}
		jerr(w, 500, err.Error())
		return
	}
	j(w, 200, map[string]any{"ok": true})
}

// pathIDN reads a named numeric path parameter.
func pathIDN(w http.ResponseWriter, r *http.Request, name string) (int64, bool) {
	v := r.PathValue(name)
	id, err := strconv.ParseInt(v, 10, 64)
	if err != nil || id <= 0 {
		jerr(w, 400, "invalid id")
		return 0, false
	}
	return id, true
}

// ---------- blocklists v2 ----------

func (s *Server) hBlocklistHistory(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	items, err := s.d.DB.BlocklistHistory(r.Context(), id, limit)
	if err != nil {
		jerr(w, 500, err.Error())
		return
	}
	j(w, 200, items)
}

func (s *Server) hBlocklistGroups(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	lgm, err := s.d.DB.ListGroupMap(r.Context())
	if err != nil {
		jerr(w, 500, err.Error())
		return
	}
	gids := lgm[id]
	if gids == nil {
		gids = []int64{}
	}
	j(w, 200, map[string]any{"group_ids": gids, "note": "empty means the list applies to all groups"})
}

func (s *Server) hBlocklistSetGroups(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var body struct {
		GroupIDs []int64 `json:"group_ids"`
	}
	if !decode(w, r, &body) {
		return
	}
	for _, g := range body.GroupIDs {
		if _, err := s.d.DB.GetGroup(r.Context(), g); err != nil {
			jerr(w, 400, fmt.Sprintf("unknown group_id %d", g))
			return
		}
	}
	if err := s.d.DB.SetBlocklistGroups(r.Context(), id, body.GroupIDs); err != nil {
		jerr(w, 500, err.Error())
		return
	}
	_ = s.d.App.ReloadRules(r.Context())
	s.d.DB.AuditEx(r.Context(), "admin", "blocklist.groups", fmt.Sprintf("list:%d", id),
		fmt.Sprintf("groups=%v", body.GroupIDs), "ok")
	j(w, 200, map[string]any{"ok": true, "group_ids": body.GroupIDs})
}

func (s *Server) hBlocklistProfiles(w http.ResponseWriter, r *http.Request) {
	j(w, 200, blocklists.Catalog)
}

// hBlocklistApplyProfile enables the profile's lists (creating missing ones)
// and refreshes them in the background.
func (s *Server) hBlocklistApplyProfile(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Profile string `json:"profile"`
	}
	if !decode(w, r, &body) {
		return
	}
	ids, err := s.d.Lists.ApplyProfile(r.Context(), body.Profile)
	if err != nil {
		jerr(w, 400, err.Error())
		return
	}
	s.d.DB.AuditEx(r.Context(), "admin", "blocklist.profile", "", body.Profile, "ok")
	for _, id := range ids {
		go s.d.Lists.Refresh(context.Background(), id)
	}
	j(w, 200, map[string]any{"ok": true, "list_ids": ids, "note": "lists refresh in background"})
}

// hBlocklistRecommendations computes pairwise overlap between enabled lists
// and per-list warnings, to surface redundancy and quality issues.
func (s *Server) hBlocklistRecommendations(w http.ResponseWriter, r *http.Request) {
	lists, err := s.d.DB.ListBlocklists(r.Context())
	if err != nil {
		jerr(w, 500, err.Error())
		return
	}
	var enabled []database.Blocklist
	for _, l := range lists {
		if l.Enabled && l.RuleCount > 0 {
			enabled = append(enabled, l)
		}
	}
	sets := map[int64]map[string]struct{}{}
	for _, l := range enabled {
		set, err := s.d.DB.ListDomains(r.Context(), l.ID)
		if err == nil {
			sets[l.ID] = set
		}
	}
	overlaps := []map[string]any{}
	names := map[int64]string{}
	sizes := map[int64]int{}
	for _, l := range enabled {
		names[l.ID] = l.Name
		sizes[l.ID] = len(sets[l.ID])
	}
	for i := 0; i < len(enabled); i++ {
		for k := i + 1; k < len(enabled); k++ {
			a, b := enabled[i], enabled[k]
			sa, sb := sets[a.ID], sets[b.ID]
			if len(sa) == 0 || len(sb) == 0 {
				continue
			}
			small, big := sa, sb
			if len(sb) < len(sa) {
				small, big = sb, sa
			}
			shared := 0
			for d := range small {
				if _, ok := big[d]; ok {
					shared++
				}
			}
			if shared > 0 {
				overlaps = append(overlaps, map[string]any{
					"a": a.ID, "a_name": a.Name, "b": b.ID, "b_name": b.Name,
					"shared":         shared,
					"pct_of_smaller": float64(shared) / float64(len(small)) * 100,
				})
			}
		}
	}
	warnings := []map[string]any{}
	for _, l := range lists {
		if l.Enabled && l.RuleCount == 0 && l.LastRefresh != "" {
			warnings = append(warnings, map[string]any{
				"list_id": l.ID, "name": l.Name, "issue": "enabled but empty — last refresh produced no domains"})
		}
		if l.LastError != "" {
			warnings = append(warnings, map[string]any{
				"list_id": l.ID, "name": l.Name, "issue": "last error: " + l.LastError})
		}
		if !l.Enabled && l.RuleCount > 50000 {
			warnings = append(warnings, map[string]any{
				"list_id": l.ID, "name": l.Name, "issue": "large list disabled — re-enable to restore coverage"})
		}
	}
	j(w, 200, map[string]any{
		"overlaps": overlaps, "warnings": warnings,
		"counts": map[string]any{"enabled_lists": len(enabled)},
	})
}

// ---------- analytics v2 ----------

func (s *Server) hStatsLatency(w http.ResponseWriter, r *http.Request) {
	st, err := s.d.DB.StatsLatency(r.Context(), parseWindow(r))
	if err != nil {
		jerr(w, 500, err.Error())
		return
	}
	j(w, 200, st)
}

func (s *Server) hStatsErrors(w http.ResponseWriter, r *http.Request) {
	items, err := s.d.DB.StatsErrors(r.Context(), parseWindow(r))
	if err != nil {
		jerr(w, 500, err.Error())
		return
	}
	for i := range items {
		items[i].Name = dns.RcodeToString[items[i].RCode]
	}
	j(w, 200, items)
}

func (s *Server) hStatsGroups(w http.ResponseWriter, r *http.Request) {
	items, err := s.d.DB.StatsByGroup(r.Context(), parseWindow(r))
	if err != nil {
		jerr(w, 500, err.Error())
		return
	}
	j(w, 200, items)
}

// hStatsDomain is the investigation view: everything known about one domain,
// plus how the engine currently treats it.
func (s *Server) hStatsDomain(w http.ResponseWriter, r *http.Request) {
	d := filtering.Normalize(r.URL.Query().Get("domain"))
	if d == "" {
		jerr(w, 400, "domain required")
		return
	}
	st, err := s.d.DB.StatsDomain(r.Context(), d)
	if err != nil {
		jerr(w, 500, err.Error())
		return
	}
	blocks, allows := s.d.Engine.DomainSources(d)
	if blocks == nil {
		blocks = map[int64]string{}
	}
	if allows == nil {
		allows = map[int64]string{}
	}
	j(w, 200, map[string]any{
		"stats":          st,
		"engine_lists":   blocks,
		"engine_excepts": allows,
		"current_rules":  s.d.Engine.MatchAll(d, filtering.Subject{Now: time.Now()}),
	})
}

func (s *Server) hClientStats(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	c, err := s.d.DB.GetClient(r.Context(), id)
	if err != nil {
		jerr(w, 404, "client not found")
		return
	}
	since := parseWindow(r)
	ts, _ := s.d.DB.ClientTimeseries(r.Context(), id, since, 48)
	top, _ := s.d.DB.ClientTopDomains(r.Context(), id, since, false, 10)
	topBlocked, _ := s.d.DB.ClientTopDomains(r.Context(), id, since, true, 10)
	j(w, 200, map[string]any{
		"client": c, "timeseries": ts, "top_domains": top, "top_blocked": topBlocked,
	})
}

func (s *Server) hUpstreamHealth(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	items, err := s.d.DB.UpstreamHealthHistory(r.Context(), id, limit)
	if err != nil {
		jerr(w, 500, err.Error())
		return
	}
	j(w, 200, items)
}

// ---------- audit v2 ----------

func (s *Server) hAuditLog(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := database.AuditFilter{
		Action: q.Get("action"), Actor: q.Get("actor"),
	}
	if v := q.Get("since"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			f.Since = t
		}
	}
	page, _ := strconv.Atoi(q.Get("page"))
	per, _ := strconv.Atoi(q.Get("per_page"))
	if per <= 0 || per > 500 {
		per = 100
	}
	if page < 1 {
		page = 1
	}
	f.Limit, f.Offset = per, (page-1)*per
	items, total, err := s.d.DB.ListAuditFiltered(r.Context(), f)
	if err != nil {
		jerr(w, 500, err.Error())
		return
	}
	j(w, 200, map[string]any{"items": items, "total": total, "page": page, "per_page": per})
}

func (s *Server) hAuditExport(w http.ResponseWriter, r *http.Request) {
	items, _, err := s.d.DB.ListAuditFiltered(r.Context(), database.AuditFilter{Limit: 10000})
	if err != nil {
		jerr(w, 500, err.Error())
		return
	}
	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", `attachment; filename="blacknet-audit.csv"`)
	fmt.Fprintln(w, "ts,actor,action,resource,result,detail")
	for _, e := range items {
		fmt.Fprintf(w, "%s,%s,%s,%s,%s,%q\n", e.TS, e.Actor, e.Action, e.Resource, e.Result, e.Detail)
	}
}

// ---------- system health / diagnostics ----------

func (s *Server) hSystemHealth(w http.ResponseWriter, r *http.Request) {
	h := s.systemHealth(r.Context())
	j(w, 200, h)
}

func (s *Server) systemHealth(ctx context.Context) map[string]any {
	checks := map[string]any{}

	// DB
	dbErr := s.d.DB.Ping(ctx)
	checks["database"] = map[string]any{"ok": dbErr == nil, "error": errStr(dbErr)}

	// DNS listeners + counters
	q, b, ref, f := s.d.DNS.Counters()
	checks["dns"] = map[string]any{
		"ok": true, "listeners": s.d.Cfg.DNS.Listen,
		"queries": q, "blocked": b, "refused": ref, "failures": f,
		"blocking_mode": s.d.DNS.BlockingMode(),
	}

	// Engine
	userRules, listDomains := s.d.Engine.ListStats()
	checks["engine"] = map[string]any{
		"protection":   s.d.Engine.ProtectionEnabled(),
		"user_rules":   userRules,
		"list_domains": listDomains,
	}

	// Upstreams
	upStats := s.d.Pool.Stats()
	healthy := 0
	var lastErr string
	for _, st := range upStats {
		if st.Healthy {
			healthy++
		}
		if st.LastError != "" {
			lastErr = st.LastError
		}
	}
	checks["upstreams"] = map[string]any{
		"healthy": healthy, "total": len(upStats), "last_error": lastErr,
	}

	// Blocklists
	lists, _ := s.d.DB.ListBlocklists(ctx)
	var stale, failing int
	for _, l := range lists {
		if l.LastError != "" {
			failing++
		}
		if l.Enabled && l.LastRefresh == "" {
			stale++
		}
	}
	checks["blocklists"] = map[string]any{
		"total": len(lists), "failing": failing, "never_refreshed": stale,
	}

	// Cache
	checks["cache"] = s.d.Cache.Stats()

	// Query writer
	checks["query_log"] = map[string]any{
		"enabled": s.d.QLog.Enabled(), "dropped": s.d.QLog.Dropped(),
	}

	// Runtime
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	checks["runtime"] = map[string]any{
		"goroutines": runtime.NumGoroutine(),
		"heap_mb":    ms.HeapAlloc / 1024 / 1024,
		"go":         runtime.Version(),
	}

	return map[string]any{
		"ok":      dbErr == nil && healthy > 0,
		"version": s.d.Version,
		"time":    time.Now().UTC().Format(time.RFC3339),
		"checks":  checks,
	}
}

// hDiagnosticsExport produces a ZIP bundle safe to share — config and
// settings have secrets stripped; nothing sensitive is included.
func (s *Server) hDiagnosticsExport(w http.ResponseWriter, r *http.Request) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	add := func(name string, data []byte) {
		f, _ := zw.Create(name)
		_, _ = f.Write(data)
	}
	addJSON := func(name string, v any) {
		b, _ := json.MarshalIndent(v, "", "  ")
		add(name, b)
	}
	addJSON("health.json", s.systemHealth(r.Context()))
	addJSON("config.json", map[string]any{
		"dns_listen":    s.d.Cfg.DNS.Listen,
		"web_listen":    s.d.Cfg.Web.Listen,
		"trusted_cidrs": s.d.Cfg.DNS.TrustedCIDRs,
		"data_dir":      s.d.Cfg.DataDir,
	})
	if lists, err := s.d.DB.ListBlocklists(r.Context()); err == nil {
		addJSON("blocklists.json", lists)
	}
	if ups, err := s.d.DB.ListUpstreams(r.Context()); err == nil {
		// Strip any credentials embedded in addresses.
		type safe struct {
			ID       int64  `json:"id"`
			Name     string `json:"name"`
			Protocol string `json:"protocol"`
			Enabled  bool   `json:"enabled"`
		}
		out := []safe{}
		for _, u := range ups {
			out = append(out, safe{u.ID, u.Name, string(u.Protocol), u.Enabled})
		}
		addJSON("upstreams.json", out)
	}
	if groups, err := s.d.DB.ListGroups(r.Context()); err == nil {
		addJSON("policy_groups.json", groups)
	}
	var mig int
	_ = s.d.DB.SQL.QueryRow(`SELECT COALESCE(MAX(version),0) FROM schema_migrations`).Scan(&mig)
	add("schema.txt", []byte(fmt.Sprintf("migration version: %d\n", mig)))
	if evts, err := s.d.DB.ListDiscoveryEvents(r.Context(), 100); err == nil {
		addJSON("discovery.json", evts)
	}
	// Recent audit entries (no secrets are ever stored in detail fields).
	if entries, _, err := s.d.DB.ListAuditFiltered(r.Context(), database.AuditFilter{Limit: 200}); err == nil {
		addJSON("audit_recent.json", entries)
	}
	if err := zw.Close(); err != nil {
		jerr(w, 500, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="blacknet-diagnostics.zip"`)
	w.Write(buf.Bytes())
}

// hNetworkProtection reports the honest, three-state enforcement view:
// configured (what we intend), observed (what we can see), enforced (verified).
func (s *Server) hNetworkProtection(w http.ResponseWriter, r *http.Request) {
	clients, _ := s.d.DB.ListClients(r.Context())
	events, _ := s.d.DB.ListDiscoveryEvents(r.Context(), 50)
	unmanaged := 0
	for _, e := range events {
		if e.Kind == "unmanaged-device" {
			unmanaged++
		}
	}
	ops, _ := s.d.DB.ListEnforcementOps(r.Context(), 10)
	var enforced *database.EnforcementOp
	for i := range ops {
		if ops[i].Status == enforcement.StApplied || ops[i].Status == enforcement.StVerified {
			enforced = &ops[i]
			break
		}
	}
	j(w, 200, map[string]any{
		"configured": map[string]any{
			"dns_listen":    s.d.Cfg.DNS.Listen,
			"trusted_cidrs": s.d.Cfg.DNS.TrustedCIDRs,
			"protection":    s.d.Engine.ProtectionEnabled(),
		},
		"observed": map[string]any{
			"known_clients":     len(clients),
			"unmanaged_devices": unmanaged,
			"host_interfaces":   discovery.Interfaces(),
			"query_log_dropped": s.d.QLog.Dropped(),
		},
		"enforced": enforced, // nil = nothing verified on the router
		"notes": []string{
			"Blacknet filters DNS sent to it; devices using hardcoded or encrypted DNS bypass it unless the router redirects port 53.",
			"'Enforced' is only reported after a verified router change (see Enforcement).",
		},
	})
}

// ---------- enforcement ----------

func (s *Server) hEnforcementIntegrations(w http.ResponseWriter, r *http.Request) {
	if s.d.Enf == nil {
		jerr(w, 503, "enforcement subsystem not initialized")
		return
	}
	var req enforcement.Request
	// Optional connection hints via query params for detect probing.
	q := r.URL.Query()
	req.Host, req.Username = q.Get("host"), q.Get("username")
	if v := q.Get("port"); v != "" {
		req.Port, _ = strconv.Atoi(v)
	}
	req.HostKey = q.Get("host_key")
	// Note: no password probing via GET — Detect without creds reports
	// "credentials required" honestly.
	j(w, 200, s.d.Enf.Integrations(r.Context(), req))
}

func (s *Server) hEnforcementPreview(w http.ResponseWriter, r *http.Request) {
	if s.d.Enf == nil {
		jerr(w, 503, "enforcement subsystem not initialized")
		return
	}
	var req enforcement.Request
	if !decode(w, r, &req) {
		return
	}
	plan, err := s.d.Enf.Preview(r.Context(), req)
	if err != nil {
		jerr(w, 400, err.Error())
		return
	}
	j(w, 200, plan)
}

func (s *Server) hEnforcementApply(w http.ResponseWriter, r *http.Request) {
	if s.d.Enf == nil {
		jerr(w, 503, "enforcement subsystem not initialized")
		return
	}
	var req enforcement.Request
	if !decode(w, r, &req) {
		return
	}
	if r.URL.Query().Get("confirm") != "true" {
		jerr(w, 400, "pass confirm=true — this modifies the target's firewall")
		return
	}
	op, err := s.d.Enf.Apply(r.Context(), req)
	if err != nil {
		jerr(w, 502, err.Error())
		return
	}
	s.d.DB.AuditEx(r.Context(), "admin", "enforcement.apply",
		req.Integration, req.Action, "ok")
	j(w, 200, op)
}

func (s *Server) hEnforcementRollback(w http.ResponseWriter, r *http.Request) {
	opID, ok := pathID(w, r)
	if !ok {
		return
	}
	if s.d.Enf == nil {
		jerr(w, 503, "enforcement subsystem not initialized")
		return
	}
	var req enforcement.Request
	if !decode(w, r, &req) {
		return
	}
	if r.URL.Query().Get("confirm") != "true" {
		jerr(w, 400, "pass confirm=true")
		return
	}
	if err := s.d.Enf.Rollback(r.Context(), opID, req); err != nil {
		jerr(w, 502, err.Error())
		return
	}
	s.d.DB.AuditEx(r.Context(), "admin", "enforcement.rollback",
		req.Integration, fmt.Sprintf("op:%d", opID), "ok")
	j(w, 200, map[string]any{"ok": true})
}

func (s *Server) hEnforcementOps(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	items, err := s.d.DB.ListEnforcementOps(r.Context(), limit)
	if err != nil {
		jerr(w, 500, err.Error())
		return
	}
	j(w, 200, items)
}
