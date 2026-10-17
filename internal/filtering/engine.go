// Package filtering implements Blacknet's deterministic domain rule engine.
//
// Rule precedence, evaluated in order:
//
//  1. Exact-domain allow rules (client-scoped rules beat global rules).
//  2. Exact-domain block rules (client-scoped beats global).
//  3. Tree rules (domain + subdomains): the most specific matching rule wins;
//     at equal specificity a client-scoped rule beats a global rule and a
//     block beats an allow.
//  4. Blocklist exceptions (@@||domain^ style allows imported from lists).
//  5. Imported blocklist domains (tree match: a listed domain blocks itself
//     and all of its subdomains).
//  6. Default: the query is allowed and forwarded upstream.
package filtering

import "sync"

// Action is the verdict a rule applies to a matching domain.
type Action string

const (
	ActionAllow Action = "allow"
	ActionBlock Action = "block"
)

// Scope controls how a rule's domain is matched.
type Scope string

const (
	// ScopeExact matches only the exact domain.
	ScopeExact Scope = "exact"
	// ScopeTree matches the domain and all of its subdomains.
	ScopeTree Scope = "tree"
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
)

// Rule is a user-defined or imported allow/block rule.
type Rule struct {
	ID       int64  `json:"id"`
	Domain   string `json:"domain"` // normalized, no trailing dot
	Action   Action `json:"action"`
	Scope    Scope  `json:"scope"`
	ClientID int64  `json:"client_id"` // 0 = applies to all clients
	Comment  string `json:"comment"`
	Enabled  bool   `json:"enabled"`
	ListID   int64  `json:"list_id,omitempty"` // set when sourced from a blocklist
}

// Decision is the outcome of evaluating a domain against the engine.
type Decision struct {
	Blocked bool   `json:"blocked"`
	Reason  Reason `json:"reason"`
	Rule    *Rule  `json:"rule,omitempty"`
	ListID  int64  `json:"list_id,omitempty"`
}

// Engine holds rule indexes and evaluates domains. The zero value is a valid
// empty engine that allows everything.
type Engine struct {
	mu            sync.RWMutex
	exact         map[string][]Rule // user exact rules keyed by domain
	tree          map[string][]Rule // user tree rules keyed by apex domain
	listBlock     map[string]int64  // imported block domains -> source list id
	listAllow     map[string]int64  // imported exception domains -> source list id
	enabled       bool
	protectionOff bool
}

func NewEngine() *Engine {
	e := &Engine{enabled: true}
	e.Replace(nil, nil, nil)
	return e
}

// Replace atomically swaps in a new rule set. blockRules/allowRules map a
// normalized domain to the blocklist id it came from; entries match the
// domain itself and all subdomains.
func (e *Engine) Replace(rules []Rule, blockRules, allowRules map[string]int64) {
	exact := make(map[string][]Rule)
	tree := make(map[string][]Rule)
	for _, r := range rules {
		if !r.Enabled {
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
	lb := make(map[string]int64, len(blockRules))
	for d, id := range blockRules {
		lb[Normalize(d)] = id
	}
	la := make(map[string]int64, len(allowRules))
	for d, id := range allowRules {
		la[Normalize(d)] = id
	}
	e.mu.Lock()
	e.exact, e.tree, e.listBlock, e.listAllow = exact, tree, lb, la
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

// Decide evaluates domain for clientID (0 = unknown client) and returns the
// deterministic outcome described in the package documentation.
func (e *Engine) Decide(domain string, clientID int64) Decision {
	domain = Normalize(domain)
	e.mu.RLock()
	defer e.mu.RUnlock()

	if e.protectionOff {
		return Decision{Blocked: false, Reason: ReasonProtectionDisabled}
	}

	// 1 & 2: exact rules, allow before block, client-scoped before global.
	if rs := e.exact[domain]; len(rs) > 0 {
		if r, ok := pickRule(rs, clientID, ActionAllow); ok {
			return Decision{Blocked: false, Reason: ReasonAllowedExact, Rule: r}
		}
		if r, ok := pickRule(rs, clientID, ActionBlock); ok {
			return Decision{Blocked: true, Reason: ReasonBlockedExact, Rule: r}
		}
	}

	// 3: tree rules, most specific match first.
	if r, ok := e.bestTreeRuleLocked(domain, clientID); ok {
		if r.Action == ActionBlock {
			return Decision{Blocked: true, Reason: ReasonBlockedCustom, Rule: r}
		}
		return Decision{Blocked: false, Reason: ReasonAllowedCustom, Rule: r}
	}

	// 4 & 5: imported lists; exception checked before block at each level so a
	// more specific exception always wins over a less specific block.
	for _, suffix := range Parents(domain) {
		if id, ok := e.listAllow[suffix]; ok {
			return Decision{Blocked: false, Reason: ReasonAllowedListEx, ListID: id}
		}
		if id, ok := e.listBlock[suffix]; ok {
			return Decision{Blocked: true, Reason: ReasonBlockedBlocklist, ListID: id}
		}
	}

	// 6: default allow.
	return Decision{Blocked: false, Reason: ReasonAllowedDefault}
}

// pickRule chooses between global (ClientID==0) and client-scoped rules of a
// given action. Client-scoped rules win.
func pickRule(rules []Rule, clientID int64, action Action) (*Rule, bool) {
	var global *Rule
	for i := range rules {
		r := &rules[i]
		if r.Action != action {
			continue
		}
		if r.ClientID != 0 && r.ClientID == clientID {
			return r, true
		}
		if r.ClientID == 0 && global == nil {
			global = r
		}
	}
	if global != nil {
		return global, true
	}
	return nil, false
}

// bestTreeRuleLocked walks domain suffixes most-specific-first and returns the
// winning tree rule. At each level a client-scoped rule beats a global one and
// a block beats an allow.
func (e *Engine) bestTreeRuleLocked(domain string, clientID int64) (*Rule, bool) {
	for _, suffix := range Parents(domain) {
		rules := e.tree[suffix]
		if len(rules) == 0 {
			continue
		}
		var scoped, global *Rule
		for i := range rules {
			r := &rules[i]
			if r.ClientID != 0 {
				if r.ClientID == clientID && (scoped == nil || r.Action == ActionBlock) {
					scoped = r
				}
			} else if global == nil || r.Action == ActionBlock {
				global = r
			}
		}
		if scoped != nil {
			return scoped, true
		}
		return global, global != nil
	}
	return nil, false
}
