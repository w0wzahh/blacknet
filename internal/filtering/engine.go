// Package filtering implements Blacknet's deterministic domain rule engine.
//
// V2 precedence, evaluated in order (documented in docs/policy-groups.md):
//
//  0. Local DNS records answer before this engine runs (dnsserver stage).
//  1. Safety: untrusted clients are REFUSED before filtering (dnsserver).
//  2. Global protection switch, then active "protection off" schedules.
//  3. Client-scoped rules: exact first, then tree (most specific suffix).
//  4. Group-scoped rules (the client's policy group): same order.
//  5. Global rules: same order.
//  6. Blocklist exception domains (@@ entries) from applicable lists.
//  7. Blocklist block domains from applicable lists (those assigned to the
//     client's group, global lists, and lists activated by schedules).
//  8. Default: allowed, forwarded upstream.
//
// Within a tier, an exact-domain rule beats a tree rule; at equal specificity
// an allow beats a block for exact rules, while a block beats an allow for
// tree rules (a narrower or more specific exception always wins at step 3/4/5
// regardless). Ties never depend on row order: rules are compared by scope
// tier, then action, then rule id.
package filtering

import (
	"fmt"
	"sync"
	"time"

	"github.com/w0wzahh/blacknet/internal/schedules"
)

// Action is the verdict a rule applies to a matching domain.
type Action string

const (
	ActionAllow Action = "allow"
	ActionBlock Action = "block"
)

// Scope controls how a rule's domain is matched.
type Scope string

const (
	ScopeExact Scope = "exact"
	ScopeTree  Scope = "tree"
)

// Reason explains why a query received its decision.
type Reason string

const (
	ReasonAllowedExact       Reason = "allowed by exact rule"
	ReasonBlockedExact       Reason = "blocked by exact rule"
	ReasonAllowedCustom      Reason = "allowed by custom rule"
	ReasonBlockedCustom      Reason = "blocked by custom rule"
	ReasonAllowedListEx      Reason = "allowed by blocklist exception"
	ReasonBlockedBlocklist   Reason = "blocked by blocklist"
	ReasonAllowedDefault     Reason = "allowed by default"
	ReasonUntrustedClient    Reason = "refused: untrusted client"
	ReasonUpstreamFailure    Reason = "upstream resolution failed"
	ReasonProtectionDisabled Reason = "protection disabled"
	ReasonScheduleOff        Reason = "protection suspended by schedule"
	ReasonExpiredRuleSkipped Reason = "rule expired"
)

// Rule is a user-defined or imported allow/block rule.
type Rule struct {
	ID        int64  `json:"id"`
	Domain    string `json:"domain"` // normalized, no trailing dot
	Action    Action `json:"action"`
	Scope     Scope  `json:"scope"`
	ClientID  int64  `json:"client_id"` // 0 = not client-scoped
	GroupID   int64  `json:"group_id"`  // 0 = not group-scoped
	Comment   string `json:"comment"`
	Enabled   bool   `json:"enabled"`
	ExpiresAt string `json:"expires_at,omitempty"` // RFC3339 UTC; empty = permanent
	ListID    int64  `json:"list_id,omitempty"`    // set when sourced from a blocklist
}

// Expired reports whether this is a temporary rule past its lifetime.
func (r Rule) Expired(now time.Time) bool {
	if r.ExpiresAt == "" {
		return false
	}
	t, err := time.Parse(time.RFC3339, r.ExpiresAt)
	return err == nil && !t.After(now)
}

// ScopeName names the tier a rule belongs to for a subject.
func (r Rule) ScopeName() string {
	switch {
	case r.ClientID != 0:
		return "client"
	case r.GroupID != 0:
		return "group"
	default:
		return "global"
	}
}

// Subject is who asked: a resolved client, its policy group, and the
// evaluation time (for schedules and temporary rules).
type Subject struct {
	ClientID int64     `json:"client_id"`
	GroupID  int64     `json:"group_id"`
	Now      time.Time `json:"now"`
}

// tier ranks how a rule applies to a subject: 0 = does not apply.
func (r Rule) tier(s Subject) int {
	switch {
	case r.ClientID != 0:
		if r.ClientID == s.ClientID {
			return 3
		}
		return 0
	case r.GroupID != 0:
		if r.GroupID == s.GroupID && s.GroupID != 0 {
			return 2
		}
		return 0
	default:
		return 1
	}
}

// Decision is the outcome of evaluating a domain against the engine.
type Decision struct {
	Blocked bool   `json:"blocked"`
	Reason  Reason `json:"reason"`
	Rule    *Rule  `json:"rule,omitempty"`
	ListID  int64  `json:"list_id,omitempty"`
}

// Step records one evaluated stage for the inspector/simulator.
type Step struct {
	Stage   string `json:"stage"`
	Matched bool   `json:"matched"`
	Detail  string `json:"detail"`
	Rule    *Rule  `json:"rule,omitempty"`
	ListID  int64  `json:"list_id,omitempty"`
}

// Explanation is a Decision plus the full evaluation trace.
type Explanation struct {
	Decision        Decision `json:"decision"`
	Subject         Subject  `json:"subject"`
	ActiveSchedules []string `json:"active_schedules,omitempty"`
	ProtectionOff   bool     `json:"protection_off"`
	Steps           []Step   `json:"steps"`
}

// Snapshot is the immutable rule set the engine serves from.
type Snapshot struct {
	Rules      []Rule
	Blocks     map[string]int64  // blocklist domain -> list id
	Allows     map[string]int64  // exception domain -> list id
	ListGroups map[int64][]int64 // list id -> restricted groups; missing = global
	// DisabledGroups inactivates a group's rules and restricted lists; its
	// members still resolve to the group but fall through to global policy.
	DisabledGroups map[int64]bool
	Schedules      []schedules.Schedule
}

// Engine holds rule indexes and evaluates domains. The zero value is a valid
// empty engine that allows everything.
type Engine struct {
	mu            sync.RWMutex
	exact         map[string][]Rule
	tree          map[string][]Rule
	listBlock     map[string]int64
	listAllow     map[string]int64
	listGroups    map[int64][]int64
	schedules     []schedules.Schedule
	enabled       bool
	protectionOff bool
}

func NewEngine() *Engine {
	e := &Engine{enabled: true}
	e.Replace(Snapshot{})
	return e
}

// Replace atomically swaps in a new snapshot. Expired rules are dropped at
// build time; Decide re-checks expiry so a rule can never come back to life
// between rebuilds.
func (e *Engine) Replace(s Snapshot) {
	now := time.Now()
	exact := make(map[string][]Rule)
	tree := make(map[string][]Rule)
	for _, r := range s.Rules {
		if !r.Enabled || r.Expired(now) {
			continue
		}
		if r.GroupID != 0 && s.DisabledGroups[r.GroupID] {
			continue
		}
		r.Domain = Normalize(r.Domain)
		switch r.Scope {
		case ScopeExact:
			exact[r.Domain] = append(exact[r.Domain], r)
		case ScopeTree:
			tree[r.Domain] = append(tree[r.Domain], r)
		}
	}
	lb := make(map[string]int64, len(s.Blocks))
	for d, id := range s.Blocks {
		lb[Normalize(d)] = id
	}
	la := make(map[string]int64, len(s.Allows))
	for d, id := range s.Allows {
		la[Normalize(d)] = id
	}
	lg := make(map[int64][]int64, len(s.ListGroups))
	for k, v := range s.ListGroups {
		var keep []int64
		for _, g := range v {
			if !s.DisabledGroups[g] {
				keep = append(keep, g)
			}
		}
		lg[k] = keep
	}
	e.mu.Lock()
	e.exact, e.tree = exact, tree
	e.listBlock, e.listAllow = lb, la
	e.listGroups = lg
	e.schedules = append([]schedules.Schedule(nil), s.Schedules...)
	e.mu.Unlock()
}

// SetProtection toggles global filtering. When disabled every query is
// allowed with ReasonProtectionDisabled; rules are preserved.
func (e *Engine) SetProtection(on bool) {
	e.mu.Lock()
	e.protectionOff = !on
	e.mu.Unlock()
}

// ProtectionEnabled reports whether filtering is active.
func (e *Engine) ProtectionEnabled() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return !e.protectionOff
}

// ListStats returns counts used by the API/dashboard.
func (e *Engine) ListStats() (userRules, listDomains int) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	for _, rs := range e.exact {
		userRules += len(rs)
	}
	for _, rs := range e.tree {
		userRules += len(rs)
	}
	return userRules, len(e.listBlock)
}

// Decide evaluates domain for sub and returns the deterministic outcome.
// It is a thin wrapper over Explain so the live path and the simulator share
// one implementation and cannot diverge.
func (e *Engine) Decide(domain string, sub Subject) Decision {
	return e.Explain(domain, sub).Decision
}

// Explain evaluates domain for sub and returns the decision with a full trace.
func (e *Engine) Explain(domain string, sub Subject) Explanation {
	domain = Normalize(domain)
	if sub.Now.IsZero() {
		sub.Now = time.Now()
	}
	e.mu.RLock()
	defer e.mu.RUnlock()

	out := Explanation{Subject: sub, Steps: []Step{}}

	// Stage: schedules. Protection-off wins over everything else except the
	// safety checks that already ran in dnsserver; protection-on re-enables
	// filtering for a subject while the global switch is off.
	var extraLists map[int64]bool
	var forceOn bool
	for i := range e.schedules {
		sc := &e.schedules[i]
		if !sc.Active(sub.Now) || !sc.Applies(sub.ClientID, sub.GroupID) {
			continue
		}
		out.ActiveSchedules = append(out.ActiveSchedules, sc.Name)
		switch sc.Effect {
		case schedules.EffectProtectionOff:
			out.Decision = Decision{Blocked: false, Reason: ReasonScheduleOff}
			out.Steps = append(out.Steps, Step{Stage: "schedule", Matched: true,
				Detail: fmt.Sprintf("schedule %q suspends filtering for this subject", sc.Name)})
			return out
		case schedules.EffectProtectionOn:
			forceOn = true
		case schedules.EffectExtraLists:
			for _, id := range sc.ListIDs {
				if extraLists == nil {
					extraLists = map[int64]bool{}
				}
				extraLists[id] = true
			}
		}
	}
	out.Steps = append(out.Steps, Step{Stage: "schedule",
		Detail: fmt.Sprintf("%d active schedule(s) for this subject", len(out.ActiveSchedules))})

	if e.protectionOff && !forceOn {
		out.ProtectionOff = true
		out.Decision = Decision{Blocked: false, Reason: ReasonProtectionDisabled}
		out.Steps = append(out.Steps, Step{Stage: "protection", Matched: true,
			Detail: "global protection switch is off"})
		return out
	}

	listApplies := func(listID int64) bool {
		if extraLists != nil && extraLists[listID] {
			return true
		}
		groups, restricted := e.listGroups[listID]
		if !restricted {
			return true // no group rows = global list
		}
		for _, g := range groups {
			if g == sub.GroupID {
				return true
			}
		}
		return false
	}

	// Stages 3-5: user rules by scope tier. Exact domains first.
	if rs := e.exact[domain]; len(rs) > 0 {
		// Highest tier wins; within a tier allow beats block, then lowest id.
		var best *Rule
		for i := range rs {
			r := &rs[i]
			if r.Expired(sub.Now) {
				continue
			}
			if r.tier(sub) == 0 {
				continue
			}
			if best == nil || r.tier(sub) > best.tier(sub) ||
				(r.tier(sub) == best.tier(sub) && r.Action == ActionAllow && best.Action == ActionBlock) ||
				(r.tier(sub) == best.tier(sub) && r.Action == best.Action && r.ID < best.ID) {
				best = r
			}
		}
		if best != nil {
			reason := ReasonAllowedExact
			if best.Action == ActionBlock {
				reason = ReasonBlockedExact
			}
			out.Decision = Decision{Blocked: best.Action == ActionBlock, Reason: reason, Rule: best}
			out.Steps = append(out.Steps, Step{Stage: "exact_rule", Matched: true, Rule: best,
				Detail: fmt.Sprintf("%s %s rule #%d wins", best.ScopeName(), best.Action, best.ID)})
			return out
		}
	}
	out.Steps = append(out.Steps, Step{Stage: "exact_rule", Detail: "no exact rule applies"})

	// Tree rules: most specific matching suffix first; at the first suffix
	// with applicable rules, highest tier wins then block beats allow, then id.
	for _, suffix := range Parents(domain) {
		rules := e.tree[suffix]
		if len(rules) == 0 {
			continue
		}
		var best *Rule
		for i := range rules {
			r := &rules[i]
			if r.Expired(sub.Now) || r.tier(sub) == 0 {
				continue
			}
			if best == nil || r.tier(sub) > best.tier(sub) ||
				(r.tier(sub) == best.tier(sub) && r.Action == ActionBlock && best.Action == ActionAllow) ||
				(r.tier(sub) == best.tier(sub) && r.Action == best.Action && r.ID < best.ID) {
				best = r
			}
		}
		if best == nil {
			continue
		}
		reason := ReasonAllowedCustom
		if best.Action == ActionBlock {
			reason = ReasonBlockedCustom
		}
		out.Decision = Decision{Blocked: best.Action == ActionBlock, Reason: reason, Rule: best}
		out.Steps = append(out.Steps, Step{Stage: "tree_rule", Matched: true, Rule: best,
			Detail: fmt.Sprintf("most specific match %q, %s rule #%d wins", suffix, best.ScopeName(), best.ID)})
		return out
	}
	out.Steps = append(out.Steps, Step{Stage: "tree_rule", Detail: "no tree rule applies"})

	// Stages 6-7: blocklists. Exceptions beat blocks at each suffix level.
	for _, suffix := range Parents(domain) {
		if id, ok := e.listAllow[suffix]; ok && listApplies(id) {
			out.Decision = Decision{Blocked: false, Reason: ReasonAllowedListEx, ListID: id}
			out.Steps = append(out.Steps, Step{Stage: "list_exception", Matched: true, ListID: id,
				Detail: fmt.Sprintf("exception for %q in list #%d", suffix, id)})
			return out
		}
		if id, ok := e.listBlock[suffix]; ok && listApplies(id) {
			out.Decision = Decision{Blocked: true, Reason: ReasonBlockedBlocklist, ListID: id}
			out.Steps = append(out.Steps, Step{Stage: "list_block", Matched: true, ListID: id,
				Detail: fmt.Sprintf("%q in blocklist #%d", suffix, id)})
			return out
		}
	}
	out.Steps = append(out.Steps, Step{Stage: "list", Detail: "no applicable list matches"})

	out.Decision = Decision{Blocked: false, Reason: ReasonAllowedDefault}
	out.Steps = append(out.Steps, Step{Stage: "default", Matched: true, Detail: "allowed by default"})
	return out
}

// DomainSources reports which blocklists contain domain or its parents —
// used by the rule inspector and "why blocked" UI.
func (e *Engine) DomainSources(domain string) (blockedBy, exceptedBy map[int64]string) {
	domain = Normalize(domain)
	e.mu.RLock()
	defer e.mu.RUnlock()
	for _, suffix := range Parents(domain) {
		if id, ok := e.listBlock[suffix]; ok {
			if blockedBy == nil {
				blockedBy = map[int64]string{}
			}
			blockedBy[id] = suffix
		}
		if id, ok := e.listAllow[suffix]; ok {
			if exceptedBy == nil {
				exceptedBy = map[int64]string{}
			}
			exceptedBy[id] = suffix
		}
	}
	return blockedBy, exceptedBy
}

// MatchAll returns every user rule (including expired/disabled) that matches
// domain for sub — used by conflict detection and the inspector.
func (e *Engine) MatchAll(domain string, sub Subject) []Rule {
	domain = Normalize(domain)
	e.mu.RLock()
	defer e.mu.RUnlock()
	var out []Rule
	for _, r := range e.exact[domain] {
		out = append(out, r)
	}
	for _, suffix := range Parents(domain) {
		out = append(out, e.tree[suffix]...)
	}
	return out
}
