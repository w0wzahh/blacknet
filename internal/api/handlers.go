package api

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/w0wzahh/blacknet/internal/database"
	"github.com/w0wzahh/blacknet/internal/filtering"
	"github.com/w0wzahh/blacknet/internal/network"
	"github.com/w0wzahh/blacknet/internal/upstream"
)

// ---------- auth / setup ----------

func (s *Server) hAuthState(w http.ResponseWriter, r *http.Request) {
	_, ok := s.authenticated(r)
	j(w, 200, map[string]any{
		"password_set":    s.d.Auth.HasPassword(),
		"authenticated":   ok,
		"setup_completed": s.d.App.GetSettings().SetupCompleted,
	})
}

func (s *Server) hLogin(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if !s.d.Auth.AllowLogin(ip) {
		jerr(w, http.StatusTooManyRequests, "too many login attempts; try again later")
		return
	}
	var body struct {
		Password string `json:"password"`
	}
	if !decode(w, r, &body) {
		return
	}
	if !s.d.Auth.CheckPassword(body.Password) {
		s.d.DB.Audit(r.Context(), "auth.login_failed", ip)
		jerr(w, http.StatusUnauthorized, "invalid password")
		return
	}
	tok := s.d.Auth.CreateSession()
	http.SetCookie(w, &http.Cookie{
		Name:     "blacknet_session",
		Value:    tok,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int((12 * time.Hour).Seconds()),
	})
	s.d.DB.Audit(r.Context(), "auth.login", ip)
	j(w, 200, map[string]any{"ok": true})
}

func (s *Server) hLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie("blacknet_session"); err == nil {
		s.d.Auth.DestroySession(c.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name: "blacknet_session", Value: "", Path: "/", HttpOnly: true,
		SameSite: http.SameSiteStrictMode, MaxAge: -1,
	})
	j(w, 200, map[string]any{"ok": true})
}

// hSetupPassword sets the initial admin password — only usable before one exists.
func (s *Server) hSetupPassword(w http.ResponseWriter, r *http.Request) {
	if s.d.Auth.HasPassword() {
		jerr(w, http.StatusConflict, "password already configured")
		return
	}
	var body struct {
		Password string `json:"password"`
	}
	if !decode(w, r, &body) {
		return
	}
	if err := s.d.Auth.SetPassword(body.Password); err != nil {
		jerr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.d.DB.SetSetting("admin.password_hash", s.d.Auth.Hash()); err != nil {
		jerr(w, 500, "persist password")
		return
	}
	s.d.DB.Audit(r.Context(), "auth.password_set", clientIP(r))
	tok := s.d.Auth.CreateSession()
	http.SetCookie(w, &http.Cookie{
		Name: "blacknet_session", Value: tok, Path: "/", HttpOnly: true,
		SameSite: http.SameSiteStrictMode, MaxAge: int((12 * time.Hour).Seconds()),
	})
	j(w, 200, map[string]any{"ok": true})
}

// ---------- status ----------

func (s *Server) hHealth(w http.ResponseWriter, r *http.Request) {
	dbOK := s.d.DB.Ping(r.Context()) == nil
	queries, _, _, _ := s.d.DNS.Counters()
	j(w, 200, map[string]any{
		"ok":              dbOK,
		"version":         s.d.Version,
		"db_ok":           dbOK,
		"dns_listeners":   s.d.Cfg.DNS.Listen,
		"queries_total":   queries,
		"setup_completed": s.d.App.GetSettings().SetupCompleted,
	})
}

func (s *Server) hStatus(w http.ResponseWriter, r *http.Request) {
	queries, blocked, refused, failures := s.d.DNS.Counters()
	st := s.d.App.GetSettings()
	userRules, listDomains := s.d.Engine.ListStats()
	cs := s.d.Cache.Stats()
	var cacheHitRate float64
	if cs.Hits+cs.Misses > 0 {
		cacheHitRate = float64(cs.Hits) / float64(cs.Hits+cs.Misses) * 100
	}
	upStats := s.d.Pool.Stats()
	upOK, upTotal := 0, 0
	for _, u := range upStats {
		upTotal++
		if u.Healthy {
			upOK++
		}
	}
	lists, _ := s.d.DB.ListBlocklists(r.Context())
	activeLists := 0
	for _, l := range lists {
		if l.Enabled {
			activeLists++
		}
	}
	clients, _ := s.d.DB.ListClients(r.Context())
	j(w, 200, map[string]any{
		"version":            s.d.Version,
		"protection_enabled": s.d.Engine.ProtectionEnabled(),
		"blocking_mode":      s.d.DNS.BlockingMode(),
		"dns_listeners":      s.d.Cfg.DNS.Listen,
		"trusted_cidrs":      s.d.Cfg.DNS.TrustedCIDRs,
		"queries_total":      queries,
		"queries_blocked":    blocked,
		"queries_refused":    refused,
		"upstream_failures":  failures,
		"log_events_dropped": s.d.QLog.Dropped(),
		"cache":              cs,
		"cache_hit_rate":     cacheHitRate,
		"upstreams_healthy":  upOK,
		"upstreams_total":    upTotal,
		"active_blocklists":  activeLists,
		"blocklist_domains":  listDomains,
		"custom_rules":       userRules,
		"known_clients":      len(clients),
		"settings":           st,
	})
}

func (s *Server) hAbout(w http.ResponseWriter, r *http.Request) {
	j(w, 200, map[string]any{
		"name":        "Blacknet",
		"version":     s.d.Version,
		"license":     "MIT",
		"description": "Self-hosted, network-wide DNS ad and tracker blocker.",
		"repository":  "",
	})
}

func (s *Server) hAudit(w http.ResponseWriter, r *http.Request) {
	items, err := s.d.DB.ListAudit(r.Context(), 200)
	if err != nil {
		jerr(w, 500, err.Error())
		return
	}
	j(w, 200, items)
}

// ---------- stats ----------

func parseWindow(r *http.Request) time.Time {
	w := r.URL.Query().Get("window")
	var d time.Duration
	switch w {
	case "1h":
		d = time.Hour
	case "24h", "":
		d = 24 * time.Hour
	case "7d":
		d = 7 * 24 * time.Hour
	case "30d":
		d = 30 * 24 * time.Hour
	default:
		if dd, err := time.ParseDuration(w); err == nil && dd > 0 && dd <= 90*24*time.Hour {
			d = dd
		} else {
			d = 24 * time.Hour
		}
	}
	return time.Now().Add(-d)
}

func (s *Server) hStatsSummary(w http.ResponseWriter, r *http.Request) {
	sum, err := s.d.DB.StatsSummary(r.Context(), parseWindow(r))
	if err != nil {
		jerr(w, 500, err.Error())
		return
	}
	j(w, 200, sum)
}

func (s *Server) hStatsTimeseries(w http.ResponseWriter, r *http.Request) {
	buckets, _ := strconv.Atoi(r.URL.Query().Get("buckets"))
	ts, err := s.d.DB.Timeseries(r.Context(), parseWindow(r), buckets)
	if err != nil {
		jerr(w, 500, err.Error())
		return
	}
	j(w, 200, ts)
}

func (s *Server) hTopDomains(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	items, err := s.d.DB.TopDomains(r.Context(), parseWindow(r),
		r.URL.Query().Get("blocked") == "true", limit)
	if err != nil {
		jerr(w, 500, err.Error())
		return
	}
	j(w, 200, items)
}

func (s *Server) hTopClients(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	items, err := s.d.DB.TopClients(r.Context(), parseWindow(r), limit)
	if err != nil {
		jerr(w, 500, err.Error())
		return
	}
	// attach aliases
	clients, _ := s.d.DB.ListClients(r.Context())
	alias := map[string]string{}
	for _, c := range clients {
		alias[c.IP] = c.Alias
	}
	type out struct {
		database.TopItem
		Alias string `json:"alias,omitempty"`
	}
	res := make([]out, 0, len(items))
	for _, it := range items {
		res = append(res, out{TopItem: it, Alias: alias[it.Value]})
	}
	j(w, 200, res)
}

// ---------- queries ----------

func (s *Server) queryFilter(r *http.Request) database.QueryFilter {
	q := r.URL.Query()
	f := database.QueryFilter{
		Domain:   q.Get("domain"),
		ClientIP: q.Get("client"),
	}
	if v := q.Get("blocked"); v != "" {
		b := v == "true" || v == "1"
		f.Blocked = &b
	}
	if v := q.Get("qtype"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			u := uint16(n)
			f.QType = &u
		}
	}
	if v := q.Get("since"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			f.Since = t
		}
	}
	if v := q.Get("until"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			f.Until = t
		}
	}
	page, _ := strconv.Atoi(q.Get("page"))
	per, _ := strconv.Atoi(q.Get("per_page"))
	if per <= 0 || per > 1000 {
		per = 100
	}
	if page < 1 {
		page = 1
	}
	f.Limit = per
	f.Offset = (page - 1) * per
	return f
}

func (s *Server) hQueries(w http.ResponseWriter, r *http.Request) {
	f := s.queryFilter(r)
	rows, total, err := s.d.DB.ListQueries(r.Context(), f)
	if err != nil {
		jerr(w, 500, err.Error())
		return
	}
	per := f.Limit
	pages := (total + int64(per) - 1) / int64(per)
	j(w, 200, map[string]any{
		"items": rows, "total": total,
		"page": f.Offset/per + 1, "per_page": per, "pages": pages,
		"dropped_events": s.d.QLog.Dropped(),
	})
}

func (s *Server) hQueriesExport(w http.ResponseWriter, r *http.Request) {
	f := s.queryFilter(r)
	f.Limit, f.Offset = 100000, 0
	rows, _, err := s.d.DB.ListQueries(r.Context(), f)
	if err != nil {
		jerr(w, 500, err.Error())
		return
	}
	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", `attachment; filename="blacknet-queries.csv"`)
	fmt.Fprintln(w, "time,client_ip,client_id,domain,qtype,blocked,reason,rcode,latency_ms,cached")
	for _, q := range rows {
		fmt.Fprintf(w, "%s,%s,%d,%s,%d,%t,%q,%d,%.1f,%t\n",
			q.Time, q.ClientIP, q.ClientID, q.Domain, q.QType, q.Blocked,
			q.Reason, q.RCode, q.LatencyMs, q.Cached)
	}
}

// ---------- clients ----------

func (s *Server) hClients(w http.ResponseWriter, r *http.Request) {
	items, err := s.d.DB.ListClients(r.Context())
	if err != nil {
		jerr(w, 500, err.Error())
		return
	}
	type out struct {
		database.Client
		BlockPct float64 `json:"block_pct"`
	}
	res := make([]out, 0, len(items))
	for _, c := range items {
		var pct float64
		if c.TotalQueries > 0 {
			pct = float64(c.BlockedQueries) / float64(c.TotalQueries) * 100
		}
		res = append(res, out{Client: c, BlockPct: pct})
	}
	j(w, 200, res)
}

func (s *Server) hClientCreate(w http.ResponseWriter, r *http.Request) {
	var body struct {
		IP    string `json:"ip"`
		Alias string `json:"alias"`
		Group string `json:"group"`
	}
	if !decode(w, r, &body) {
		return
	}
	if _, err := parseIP(body.IP); err != nil {
		jerr(w, 400, "invalid ip")
		return
	}
	id, err := s.d.DB.UpsertClientSeen(r.Context(), body.IP, false)
	if err != nil {
		jerr(w, 500, err.Error())
		return
	}
	if err := s.d.DB.UpdateClient(r.Context(), id, database.ClientUpdate{
		Alias: body.Alias, Group: body.Group,
	}); err != nil {
		jerr(w, 500, err.Error())
		return
	}
	c, _ := s.d.DB.GetClient(r.Context(), id)
	s.d.DB.Audit(r.Context(), "client.create", body.IP)
	j(w, 201, c)
}

func (s *Server) hClientPatch(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var body struct {
		Alias          *string `json:"alias"`
		Group          *string `json:"group"`
		PolicyGroupID  *int64  `json:"policy_group_id"`
		Classification *string `json:"classification"`
		Notes          *string `json:"notes"`
	}
	if !decode(w, r, &body) {
		return
	}
	c, err := s.d.DB.GetClient(r.Context(), id)
	if errors.Is(err, database.ErrNotFound) {
		jerr(w, 404, "client not found")
		return
	}
	if err != nil {
		jerr(w, 500, err.Error())
		return
	}
	u := database.ClientUpdate{
		Alias: c.Alias, Group: c.Group, PolicyGroupID: c.PolicyGroupID,
		Classification: c.Classification, Notes: c.Notes,
	}
	if body.Alias != nil {
		u.Alias = *body.Alias
	}
	if body.Group != nil {
		u.Group = *body.Group
	}
	if body.PolicyGroupID != nil {
		if *body.PolicyGroupID != 0 {
			if _, err := s.d.DB.GetGroup(r.Context(), *body.PolicyGroupID); err != nil {
				jerr(w, 400, "unknown policy group")
				return
			}
		}
		u.PolicyGroupID = *body.PolicyGroupID
	}
	if body.Classification != nil {
		switch *body.Classification {
		case "unknown", "phone", "computer", "tv", "iot", "printer", "router", "server", "game-console":
			u.Classification = *body.Classification
		default:
			jerr(w, 400, "unknown classification")
			return
		}
	}
	if body.Notes != nil {
		u.Notes = *body.Notes
	}
	if err := s.d.DB.UpdateClient(r.Context(), id, u); err != nil {
		jerr(w, 500, err.Error())
		return
	}
	if body.PolicyGroupID != nil {
		_ = s.d.App.ReloadPolicies(r.Context())
	}
	s.d.DB.Audit(r.Context(), "client.update", c.IP)
	c, _ = s.d.DB.GetClient(r.Context(), id)
	j(w, 200, c)
}

func (s *Server) hClientDelete(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	c, err := s.d.DB.GetClient(r.Context(), id)
	if err == nil {
		if ip, err2 := parseIP(c.IP); err2 == nil {
			s.d.QLog.ForgetClient(ip)
		}
	}
	if err := s.d.DB.DeleteClient(r.Context(), id); err != nil {
		if errors.Is(err, database.ErrNotFound) {
			jerr(w, 404, "client not found")
			return
		}
		jerr(w, 500, err.Error())
		return
	}
	s.d.DB.Audit(r.Context(), "client.delete", fmt.Sprint(id))
	j(w, 200, map[string]any{"ok": true})
}

func (s *Server) hClientReset(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if r.URL.Query().Get("confirm") != "true" {
		jerr(w, 400, "pass confirm=true to reset statistics")
		return
	}
	if err := s.d.DB.ResetClientStats(r.Context(), id); err != nil {
		if errors.Is(err, database.ErrNotFound) {
			jerr(w, 404, "client not found")
			return
		}
		jerr(w, 500, err.Error())
		return
	}
	s.d.DB.Audit(r.Context(), "client.reset_stats", fmt.Sprint(id))
	j(w, 200, map[string]any{"ok": true})
}

func (s *Server) hClientQueries(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	c, err := s.d.DB.GetClient(r.Context(), id)
	if errors.Is(err, database.ErrNotFound) {
		jerr(w, 404, "client not found")
		return
	}
	if err != nil {
		jerr(w, 500, err.Error())
		return
	}
	f := s.queryFilter(r)
	f.ClientIP = c.IP
	rows, total, err := s.d.DB.ListQueries(r.Context(), f)
	if err != nil {
		jerr(w, 500, err.Error())
		return
	}
	j(w, 200, map[string]any{"items": rows, "total": total})
}

// ---------- blocklists ----------

func (s *Server) hBlocklists(w http.ResponseWriter, r *http.Request) {
	items, err := s.d.DB.ListBlocklists(r.Context())
	if err != nil {
		jerr(w, 500, err.Error())
		return
	}
	j(w, 200, items)
}

func (s *Server) hBlocklistCreate(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name string `json:"name"`
		URL  string `json:"url"`
	}
	if !decode(w, r, &body) {
		return
	}
	body.Name = strings.TrimSpace(body.Name)
	body.URL = strings.TrimSpace(body.URL)
	if body.Name == "" {
		jerr(w, 400, "name required")
		return
	}
	if err := s.d.Lists.ValidateURL(body.URL); err != nil {
		jerr(w, 400, "url rejected: "+err.Error())
		return
	}
	bl, err := s.d.DB.AddBlocklist(r.Context(), body.Name, body.URL)
	if errors.Is(err, database.ErrDuplicate) {
		jerr(w, 409, "a blocklist with this URL already exists")
		return
	}
	if err != nil {
		jerr(w, 500, err.Error())
		return
	}
	s.d.DB.Audit(r.Context(), "blocklist.add", body.URL)
	// Kick off the first download in the background.
	go s.d.Lists.Refresh(context.Background(), bl.ID)
	j(w, 201, bl)
}

func (s *Server) hBlocklistPatch(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var body struct {
		Enabled *bool   `json:"enabled"`
		Name    *string `json:"name"`
		URL     *string `json:"url"`
	}
	if !decode(w, r, &body) {
		return
	}
	if body.Enabled != nil {
		if err := s.d.DB.SetBlocklistEnabled(r.Context(), id, *body.Enabled); err != nil {
			if errors.Is(err, database.ErrNotFound) {
				jerr(w, 404, "blocklist not found")
				return
			}
			jerr(w, 500, err.Error())
			return
		}
	}
	if body.Name != nil || body.URL != nil {
		cur, err := s.d.DB.GetBlocklist(r.Context(), id)
		if err != nil {
			jerr(w, 404, "blocklist not found")
			return
		}
		name, urlv := cur.Name, cur.URL
		if body.Name != nil {
			name = strings.TrimSpace(*body.Name)
		}
		if body.URL != nil {
			urlv = strings.TrimSpace(*body.URL)
			if err := s.d.Lists.ValidateURL(urlv); err != nil {
				jerr(w, 400, "url rejected: "+err.Error())
				return
			}
		}
		if err := s.d.DB.RenameBlocklist(r.Context(), id, name, urlv); err != nil {
			jerr(w, 500, err.Error())
			return
		}
	}
	if err := s.d.App.ReloadRules(r.Context()); err != nil {
		jerr(w, 500, "reload rules: "+err.Error())
		return
	}
	bl, _ := s.d.DB.GetBlocklist(r.Context(), id)
	j(w, 200, bl)
}

func (s *Server) hBlocklistDelete(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if err := s.d.DB.DeleteBlocklist(r.Context(), id); err != nil {
		if errors.Is(err, database.ErrNotFound) {
			jerr(w, 404, "blocklist not found")
			return
		}
		jerr(w, 500, err.Error())
		return
	}
	_ = s.d.App.ReloadRules(r.Context())
	s.d.DB.Audit(r.Context(), "blocklist.delete", fmt.Sprint(id))
	j(w, 200, map[string]any{"ok": true})
}

func (s *Server) hBlocklistRefresh(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	res, err := s.d.Lists.Refresh(r.Context(), id)
	if err != nil {
		if errors.Is(err, database.ErrNotFound) {
			jerr(w, 404, "blocklist not found")
			return
		}
		jerr(w, 502, "refresh failed: "+err.Error())
		return
	}
	j(w, 200, res)
}

func (s *Server) hBlocklistValidate(w http.ResponseWriter, r *http.Request) {
	var body struct {
		URL string `json:"url"`
	}
	if !decode(w, r, &body) {
		return
	}
	if err := s.d.Lists.ValidateURL(body.URL); err != nil {
		j(w, 200, map[string]any{"valid": false, "error": err.Error()})
		return
	}
	j(w, 200, map[string]any{"valid": true})
}

// ---------- rules ----------

func (s *Server) hRules(w http.ResponseWriter, r *http.Request) {
	items, err := s.d.DB.ListRules(r.Context())
	if err != nil {
		jerr(w, 500, err.Error())
		return
	}
	j(w, 200, items)
}

func validateRuleInput(domain, action, scope string) (string, filtering.Action, filtering.Scope, string) {
	d := strings.TrimSpace(strings.ToLower(domain))
	if strings.HasPrefix(d, "*.") {
		scope = string(filtering.ScopeTree)
		d = d[2:]
	}
	if !filtering.IsValidDomain(d) {
		return "", "", "", "invalid domain"
	}
	var a filtering.Action
	switch action {
	case "allow":
		a = filtering.ActionAllow
	case "block":
		a = filtering.ActionBlock
	default:
		return "", "", "", "action must be allow or block"
	}
	var sc filtering.Scope
	switch scope {
	case "exact", "":
		sc = filtering.ScopeExact
	case "tree":
		sc = filtering.ScopeTree
	default:
		return "", "", "", "scope must be exact or tree"
	}
	return d, a, sc, ""
}

func (s *Server) hRuleCreate(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Domain   string `json:"domain"`
		Action   string `json:"action"`
		Scope    string `json:"scope"`
		ClientID int64  `json:"client_id"`
		GroupID  int64  `json:"group_id"`
		Comment  string `json:"comment"`
		Enabled  *bool  `json:"enabled"`
		// Temporary rule: either an RFC3339 deadline or a lifetime in minutes.
		ExpiresAt        string `json:"expires_at"`
		ExpiresInMinutes int    `json:"expires_in_minutes"`
	}
	if !decode(w, r, &body) {
		return
	}
	d, a, sc, errMsg := validateRuleInput(body.Domain, body.Action, body.Scope)
	if errMsg != "" {
		jerr(w, 400, errMsg)
		return
	}
	if body.ClientID != 0 && body.GroupID != 0 {
		jerr(w, 400, "a rule is either client-scoped or group-scoped, not both")
		return
	}
	exp, errMsg := parseExpiry(body.ExpiresAt, body.ExpiresInMinutes)
	if errMsg != "" {
		jerr(w, 400, errMsg)
		return
	}
	rule := filtering.Rule{Domain: d, Action: a, Scope: sc, ClientID: body.ClientID,
		GroupID: body.GroupID, Comment: body.Comment, Enabled: true, ExpiresAt: exp}
	if body.Enabled != nil {
		rule.Enabled = *body.Enabled
	}
	if err := s.d.DB.AddRule(r.Context(), &rule); err != nil {
		if errors.Is(err, database.ErrDuplicate) {
			jerr(w, 409, "an identical rule already exists")
			return
		}
		jerr(w, 500, err.Error())
		return
	}
	_ = s.d.App.ReloadRules(r.Context())
	s.d.DB.Audit(r.Context(), "rule.add", d+" "+string(a))
	j(w, 201, rule)
}

func (s *Server) hRulePatch(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var body struct {
		Domain    *string `json:"domain"`
		Action    *string `json:"action"`
		Scope     *string `json:"scope"`
		ClientID  *int64  `json:"client_id"`
		GroupID   *int64  `json:"group_id"`
		Comment   *string `json:"comment"`
		Enabled   *bool   `json:"enabled"`
		ExpiresAt *string `json:"expires_at"` // RFC3339 or "" to make permanent
	}
	if !decode(w, r, &body) {
		return
	}
	rules, err := s.d.DB.ListRules(r.Context())
	if err != nil {
		jerr(w, 500, err.Error())
		return
	}
	var cur *filtering.Rule
	for i := range rules {
		if rules[i].ID == id {
			cur = &rules[i]
		}
	}
	if cur == nil {
		jerr(w, 404, "rule not found")
		return
	}
	rule := *cur
	if body.Domain != nil {
		rule.Domain = *body.Domain
	}
	if body.Action != nil {
		rule.Action = filtering.Action(*body.Action)
	}
	if body.Scope != nil {
		rule.Scope = filtering.Scope(*body.Scope)
	}
	if body.ClientID != nil {
		rule.ClientID = *body.ClientID
	}
	if body.GroupID != nil {
		rule.GroupID = *body.GroupID
	}
	if body.Comment != nil {
		rule.Comment = *body.Comment
	}
	if body.Enabled != nil {
		rule.Enabled = *body.Enabled
	}
	if body.ExpiresAt != nil {
		if *body.ExpiresAt == "" {
			rule.ExpiresAt = ""
		} else if exp, m := parseExpiry(*body.ExpiresAt, 0); m != "" {
			jerr(w, 400, m)
			return
		} else {
			rule.ExpiresAt = exp
		}
	}
	if rule.ClientID != 0 && rule.GroupID != 0 {
		jerr(w, 400, "a rule is either client-scoped or group-scoped, not both")
		return
	}
	d, a, sc, errMsg := validateRuleInput(rule.Domain, string(rule.Action), string(rule.Scope))
	if errMsg != "" {
		jerr(w, 400, errMsg)
		return
	}
	rule.Domain, rule.Action, rule.Scope = d, a, sc
	if err := s.d.DB.UpdateRule(r.Context(), &rule); err != nil {
		if errors.Is(err, database.ErrDuplicate) {
			jerr(w, 409, "an identical rule already exists")
			return
		}
		jerr(w, 500, err.Error())
		return
	}
	_ = s.d.App.ReloadRules(r.Context())
	s.d.DB.Audit(r.Context(), "rule.update", fmt.Sprint(id))
	j(w, 200, rule)
}

func (s *Server) hRuleDelete(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if err := s.d.DB.DeleteRule(r.Context(), id); err != nil {
		if errors.Is(err, database.ErrNotFound) {
			jerr(w, 404, "rule not found")
			return
		}
		jerr(w, 500, err.Error())
		return
	}
	_ = s.d.App.ReloadRules(r.Context())
	s.d.DB.Audit(r.Context(), "rule.delete", fmt.Sprint(id))
	j(w, 200, map[string]any{"ok": true})
}

func (s *Server) hRuleTest(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Domain   string `json:"domain"`
		ClientID int64  `json:"client_id"`
		GroupID  *int64 `json:"group_id"`
	}
	if !decode(w, r, &body) {
		return
	}
	d := filtering.Normalize(body.Domain)
	if d == "" {
		jerr(w, 400, "domain required")
		return
	}
	sub := s.testSubject(r.Context(), body.ClientID, body.GroupID)
	j(w, 200, s.d.Engine.Explain(d, sub))
}

// testSubject resolves the group for a simulator subject the same way the
// DNS path does (client assignment → resolver), with an optional explicit
// group override for what-if testing.
func (s *Server) testSubject(ctx context.Context, clientID int64, groupOverride *int64) filtering.Subject {
	sub := filtering.Subject{ClientID: clientID, Now: time.Now()}
	if groupOverride != nil {
		sub.GroupID = *groupOverride
		return sub
	}
	if clientID != 0 {
		if c, err := s.d.DB.GetClient(ctx, clientID); err == nil {
			if ip, err2 := parseIP(c.IP); err2 == nil {
				sub.GroupID = s.d.App.PolicyResolver().GroupFor(ip, clientID)
			}
		}
	}
	return sub
}

// parseExpiry normalizes a temporary-rule deadline. Pass an RFC3339 string
// or a positive lifetime in minutes; both empty = permanent.
func parseExpiry(at string, minutes int) (string, string) {
	if minutes > 0 {
		if minutes > 365*24*60 {
			return "", "expires_in_minutes too large (max 1 year)"
		}
		return time.Now().Add(time.Duration(minutes) * time.Minute).UTC().Format(time.RFC3339), ""
	}
	if at == "" {
		return "", ""
	}
	t, err := time.Parse(time.RFC3339, at)
	if err != nil {
		return "", "expires_at must be RFC3339 (e.g. 2025-01-31T20:00:00Z)"
	}
	if !t.After(time.Now()) {
		return "", "expires_at is already in the past"
	}
	return t.UTC().Format(time.RFC3339), ""
}

func (s *Server) hRulesExport(w http.ResponseWriter, r *http.Request) {
	rules, err := s.d.DB.ListRules(r.Context())
	if err != nil {
		jerr(w, 500, err.Error())
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="blacknet-rules.txt"`)
	for _, ru := range rules {
		dom := ru.Domain
		if ru.Scope == filtering.ScopeTree {
			dom = "*." + dom
		}
		fmt.Fprintf(w, "%s %s # client=%d enabled=%t %s\n",
			ru.Action, dom, ru.ClientID, ru.Enabled, ru.Comment)
	}
}

func (s *Server) hRulesImport(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Text string `json:"text"`
	}
	if !decode(w, r, &body) {
		return
	}
	added, skipped, failed := 0, 0, []string{}
	for i, line := range strings.Split(body.Text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			failed = append(failed, fmt.Sprintf("line %d: expected '<allow|block> <domain>'", i+1))
			continue
		}
		action, domain := fields[0], fields[1]
		scope := "exact"
		if strings.HasPrefix(domain, "*.") {
			scope = "tree"
		}
		d, a, sc, errMsg := validateRuleInput(domain, action, scope)
		if errMsg != "" {
			failed = append(failed, fmt.Sprintf("line %d: %s", i+1, errMsg))
			continue
		}
		comment := ""
		if idx := strings.Index(line, "#"); idx > 0 {
			comment = strings.TrimSpace(line[idx+1:])
		}
		rule := filtering.Rule{Domain: d, Action: a, Scope: sc, Comment: comment, Enabled: true}
		if err := s.d.DB.AddRule(r.Context(), &rule); err != nil {
			if errors.Is(err, database.ErrDuplicate) {
				skipped++
				continue
			}
			failed = append(failed, fmt.Sprintf("line %d: %s", i+1, err.Error()))
			continue
		}
		added++
	}
	_ = s.d.App.ReloadRules(r.Context())
	s.d.DB.Audit(r.Context(), "rule.import", fmt.Sprintf("added=%d skipped=%d", added, skipped))
	j(w, 200, map[string]any{"added": added, "skipped_duplicates": skipped, "errors": failed})
}

// ---------- upstreams ----------

func (s *Server) hUpstreams(w http.ResponseWriter, r *http.Request) {
	cfgs, err := s.d.DB.ListUpstreams(r.Context())
	if err != nil {
		jerr(w, 500, err.Error())
		return
	}
	stats := s.d.Pool.Stats()
	type out struct {
		upstream.Config
		Stats upstream.Stats `json:"stats"`
	}
	res := make([]out, 0, len(cfgs))
	for _, c := range cfgs {
		res = append(res, out{Config: c, Stats: stats[c.ID]})
	}
	j(w, 200, res)
}

func (s *Server) hUpstreamCreate(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name     string `json:"name"`
		Protocol string `json:"protocol"`
		Address  string `json:"address"`
		Priority int    `json:"priority"`
		Timeout  int    `json:"timeout_ms"`
		Enabled  *bool  `json:"enabled"`
	}
	if !decode(w, r, &body) {
		return
	}
	if body.Timeout <= 0 {
		body.Timeout = 5000
	}
	c := upstream.Config{
		Name: strings.TrimSpace(body.Name), Protocol: upstream.Protocol(body.Protocol),
		Address: strings.TrimSpace(body.Address), Priority: body.Priority,
		Timeout: time.Duration(body.Timeout) * time.Millisecond, Enabled: true,
	}
	if body.Enabled != nil {
		c.Enabled = *body.Enabled
	}
	if c.Name == "" {
		c.Name = c.Address
	}
	if err := c.Validate(); err != nil {
		jerr(w, 400, err.Error())
		return
	}
	if err := s.d.DB.AddUpstream(r.Context(), &c); err != nil {
		jerr(w, 500, err.Error())
		return
	}
	if err := s.d.App.ReloadUpstreams(r.Context()); err != nil {
		jerr(w, 500, "reload upstreams: "+err.Error())
		return
	}
	s.d.DB.Audit(r.Context(), "upstream.add", c.Address)
	j(w, 201, c)
}

func (s *Server) hUpstreamPatch(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	cfgs, err := s.d.DB.ListUpstreams(r.Context())
	if err != nil {
		jerr(w, 500, err.Error())
		return
	}
	var cur *upstream.Config
	for i := range cfgs {
		if cfgs[i].ID == id {
			cur = &cfgs[i]
		}
	}
	if cur == nil {
		jerr(w, 404, "upstream not found")
		return
	}
	var body struct {
		Name     *string `json:"name"`
		Protocol *string `json:"protocol"`
		Address  *string `json:"address"`
		Priority *int    `json:"priority"`
		Timeout  *int    `json:"timeout_ms"`
		Enabled  *bool   `json:"enabled"`
	}
	if !decode(w, r, &body) {
		return
	}
	c := *cur
	if body.Name != nil {
		c.Name = *body.Name
	}
	if body.Protocol != nil {
		c.Protocol = upstream.Protocol(*body.Protocol)
	}
	if body.Address != nil {
		c.Address = *body.Address
	}
	if body.Priority != nil {
		c.Priority = *body.Priority
	}
	if body.Timeout != nil {
		c.Timeout = time.Duration(*body.Timeout) * time.Millisecond
	}
	if body.Enabled != nil {
		c.Enabled = *body.Enabled
	}
	if err := c.Validate(); err != nil {
		jerr(w, 400, err.Error())
		return
	}
	if err := s.d.DB.UpdateUpstream(r.Context(), &c); err != nil {
		jerr(w, 500, err.Error())
		return
	}
	if err := s.d.App.ReloadUpstreams(r.Context()); err != nil {
		jerr(w, 500, "reload upstreams: "+err.Error())
		return
	}
	s.d.DB.Audit(r.Context(), "upstream.update", fmt.Sprint(id))
	j(w, 200, c)
}

func (s *Server) hUpstreamDelete(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if err := s.d.DB.DeleteUpstream(r.Context(), id); err != nil {
		if errors.Is(err, database.ErrNotFound) {
			jerr(w, 404, "upstream not found")
			return
		}
		jerr(w, 500, err.Error())
		return
	}
	if err := s.d.App.ReloadUpstreams(r.Context()); err != nil {
		jerr(w, 500, "reload upstreams: "+err.Error())
		return
	}
	s.d.DB.Audit(r.Context(), "upstream.delete", fmt.Sprint(id))
	j(w, 200, map[string]any{"ok": true})
}

// hUpstreamTest performs a real resolution. Body: {id} to test one, or a full
// config for an unsaved resolver, or {} to test all.
func (s *Server) hUpstreamTest(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ID       int64  `json:"id"`
		Protocol string `json:"protocol"`
		Address  string `json:"address"`
		Timeout  int    `json:"timeout_ms"`
		Domain   string `json:"domain"`
	}
	if !decode(w, r, &body) {
		return
	}
	probe := body.Domain
	if probe == "" {
		probe = s.d.App.GetSettings().HealthProbeDomain
	}
	if probe == "" {
		probe = "example.com"
	}
	if body.Protocol != "" && body.Address != "" {
		c := upstream.Config{
			Protocol: upstream.Protocol(body.Protocol), Address: body.Address,
			Timeout: time.Duration(body.Timeout) * time.Millisecond, Enabled: true,
		}
		if c.Timeout <= 0 {
			c.Timeout = 5 * time.Second
		}
		if err := c.Validate(); err != nil {
			jerr(w, 400, err.Error())
			return
		}
		pool, err := upstream.NewPool([]upstream.Config{c}, false)
		if err != nil {
			jerr(w, 400, err.Error())
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), c.Timeout+2*time.Second)
		defer cancel()
		stats := pool.Test(ctx, probe)
		for _, st := range stats {
			j(w, 200, st)
			return
		}
		jerr(w, 500, "no result")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	stats := s.d.Pool.Test(ctx, probe)
	if body.ID != 0 {
		if st, ok := stats[body.ID]; ok {
			j(w, 200, st)
			return
		}
		jerr(w, 404, "upstream not found or disabled")
		return
	}
	j(w, 200, stats)
}

// ---------- settings ----------

func (s *Server) hSettingsGet(w http.ResponseWriter, r *http.Request) {
	j(w, 200, s.d.App.GetSettings())
}

func (s *Server) hSettingsPatch(w http.ResponseWriter, r *http.Request) {
	var patch map[string]json.RawMessage
	if !decode(w, r, &patch) {
		return
	}
	// Never allow secret-looking keys to be set through this endpoint.
	for k := range patch {
		if strings.Contains(strings.ToLower(k), "password") || strings.Contains(strings.ToLower(k), "token") {
			jerr(w, 400, "credential fields cannot be changed here")
			return
		}
	}
	out, errs, err := s.d.App.UpdateSettings(r.Context(), patch)
	if err != nil {
		jerr(w, 500, err.Error())
		return
	}
	if len(errs) > 0 {
		jerrFields(w, 400, "validation failed", errs)
		return
	}
	s.d.DB.Audit(r.Context(), "settings.update", strings.Join(keysOf(patch), ","))
	j(w, 200, out)
}

func keysOf(m map[string]json.RawMessage) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// ---------- actions ----------

func (s *Server) hCacheFlush(w http.ResponseWriter, r *http.Request) {
	s.d.Cache.Flush()
	s.d.DB.Audit(r.Context(), "cache.flush", "")
	j(w, 200, map[string]any{"ok": true})
}

func (s *Server) hProtection(on bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !on && r.URL.Query().Get("confirm") != "true" {
			jerr(w, 400, "pass confirm=true; disabling protection lets queries resolve unfiltered")
			return
		}
		_, _, err := s.d.App.UpdateSettings(r.Context(), map[string]json.RawMessage{
			"protection_enabled": json.RawMessage(strconv.FormatBool(on)),
		})
		if err != nil {
			jerr(w, 500, err.Error())
			return
		}
		s.d.DB.Audit(r.Context(), map[bool]string{true: "protection.enable", false: "protection.disable"}[on], "")
		j(w, 200, map[string]any{"protection_enabled": on})
	}
}

// ---------- network / diagnostics ----------

func (s *Server) hInterfaces(w http.ResponseWriter, r *http.Request) {
	ifs, err := network.Interfaces()
	if err != nil {
		jerr(w, 500, err.Error())
		return
	}
	j(w, 200, ifs)
}

func (s *Server) hNetworkInfo(w http.ResponseWriter, r *http.Request) {
	ip, _ := network.PrimaryIPv4()
	portFree := map[string]bool{}
	for _, addr := range s.d.Cfg.DNS.Listen {
		u, t, _ := network.CheckDNSPort(addr)
		// port is in use by ourselves once running — report both ways
		portFree[addr] = u && t
	}
	j(w, 200, map[string]any{
		"primary_ipv4":   ip,
		"gateway_guess":  network.GatewayGuess(),
		"dns_listen":     s.d.Cfg.DNS.Listen,
		"web_listen":     s.d.Cfg.Web.Listen,
		"trusted_cidrs":  s.d.Cfg.DNS.TrustedCIDRs,
		"port_available": portFree,
	})
}

func (s *Server) hPortCheck(w http.ResponseWriter, r *http.Request) {
	addr := r.URL.Query().Get("addr")
	if addr == "" {
		jerr(w, 400, "addr required")
		return
	}
	udpOK, tcpOK, err := network.CheckDNSPort(addr)
	j(w, 200, map[string]any{
		"addr": addr, "udp_free": udpOK, "tcp_free": tcpOK,
		"error": errStr(err),
	})
}

func errStr(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func (s *Server) hDiagnostics(w http.ResponseWriter, r *http.Request) {
	domain := filtering.Normalize(r.URL.Query().Get("domain"))
	if domain == "" {
		domain = "ads.example.com"
	}
	dec := s.d.Engine.Decide(domain, filtering.Subject{Now: time.Now()})
	dbOK := s.d.DB.Ping(r.Context()) == nil
	// is the caller a known client?
	callerIP := clientIP(r)
	clients, _ := s.d.DB.ListClients(r.Context())
	callerKnown := false
	for _, c := range clients {
		if c.IP == callerIP {
			callerKnown = true
		}
	}
	upStats := s.d.Pool.Stats()
	healthy := 0
	for _, st := range upStats {
		if st.Healthy {
			healthy++
		}
	}
	j(w, 200, map[string]any{
		"dns_service":        "running",
		"db_ok":              dbOK,
		"test_domain":        domain,
		"test_decision":      dec,
		"protection_enabled": s.d.Engine.ProtectionEnabled(),
		"upstreams_healthy":  healthy,
		"upstreams_total":    len(upStats),
		"caller_ip":          callerIP,
		"caller_known":       callerKnown,
	})
}

// ---------- openapi / spa ----------

//go:embed openapi.yaml
var openapiYAML []byte

func (s *Server) hOpenAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/yaml")
	w.Write(openapiYAML)
}

func (s *Server) spaHandler() http.Handler {
	root := s.d.WebRoot
	if root == "" {
		root = "web/dist"
	}
	fs := http.FileServer(http.Dir(root))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// API paths must never receive the SPA HTML: a missed route would be
		// returned as a 200 text/html body and silently confuse api clients.
		if strings.HasPrefix(r.URL.Path, "/api/") {
			jerr(w, 404, "unknown api endpoint")
			return
		}
		// SPA fallback: serve index.html for non-file GETs.
		p := strings.TrimPrefix(r.URL.Path, "/")
		if p != "" && !strings.Contains(p, "..") && fileExists(root+"/"+p) {
			fs.ServeHTTP(w, r)
			return
		}
		http.ServeFile(w, r, root+"/index.html")
	})
}

func fileExists(p string) bool {
	f, err := http.Dir(".").Open(p)
	if err != nil {
		return false
	}
	f.Close()
	return true
}
