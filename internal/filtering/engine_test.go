package filtering

import (
	"testing"
	"time"

	"github.com/w0wzahh/blacknet/internal/schedules"
)

func TestNormalize(t *testing.T) {
	cases := map[string]string{
		"Example.COM.": "example.com",
		"  Ads.Com  ":  "ads.com",
		"a.b.c.":       "a.b.c",
	}
	for in, want := range cases {
		if got := Normalize(in); got != want {
			t.Errorf("Normalize(%q)=%q want %q", in, got, want)
		}
	}
}

func TestIsValidDomain(t *testing.T) {
	valid := []string{"example.com", "a-b.example.com", "*.example.com", "x.y.z"}
	invalid := []string{"", "-bad.com", "bad-.com", "exa mple.com", ".com", "a..b.com", "exam ple"}
	for _, d := range valid {
		if !IsValidDomain(d) {
			t.Errorf("expected valid: %q", d)
		}
	}
	for _, d := range invalid {
		if IsValidDomain(d) {
			t.Errorf("expected invalid: %q", d)
		}
	}
}

func TestParents(t *testing.T) {
	got := Parents("a.b.example.com")
	want := []string{"a.b.example.com", "b.example.com", "example.com", "com"}
	if len(got) != len(want) {
		t.Fatalf("Parents len %d want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Parents[%d]=%q want %q", i, got[i], want[i])
		}
	}
}

func engineWith(rules []Rule, blocks, allows map[string]int64) *Engine {
	e := NewEngine()
	e.Replace(Snapshot{Rules: rules, Blocks: blocks, Allows: allows})
	return e
}

func TestPrecedenceExactAllowBeatsBlock(t *testing.T) {
	e := engineWith([]Rule{
		{ID: 1, Domain: "a.com", Action: ActionAllow, Scope: ScopeExact, Enabled: true},
		{ID: 2, Domain: "a.com", Action: ActionBlock, Scope: ScopeExact, Enabled: true},
	}, nil, nil)
	d := e.Decide("a.com", Subject{})
	if d.Blocked || d.Reason != ReasonAllowedExact {
		t.Fatalf("got %+v", d)
	}
}

func TestAllowOverridesBlocklist(t *testing.T) {
	e := engineWith([]Rule{
		{ID: 1, Domain: "ads.com", Action: ActionAllow, Scope: ScopeExact, Enabled: true},
	}, map[string]int64{"ads.com": 7}, nil)
	d := e.Decide("ads.com", Subject{})
	if d.Blocked {
		t.Fatalf("allow rule should override blocklist, got %+v", d)
	}
}

func TestBlocklistBlocksSubdomains(t *testing.T) {
	e := engineWith(nil, map[string]int64{"ads.com": 3}, nil)
	for _, d := range []string{"ads.com", "www.ads.com", "deep.www.ads.com"} {
		dec := e.Decide(d, Subject{})
		if !dec.Blocked || dec.ListID != 3 {
			t.Fatalf("domain %s not blocked: %+v", d, dec)
		}
	}
	if e.Decide("notads.com", Subject{}).Blocked {
		t.Fatal("notads.com should not be blocked")
	}
	if e.Decide("ads.com.evil.com", Subject{}).Blocked {
		t.Fatal("suffix spoof should not match")
	}
}

func TestTreeRuleMoreSpecificWins(t *testing.T) {
	e := engineWith([]Rule{
		{ID: 1, Domain: "example.com", Action: ActionBlock, Scope: ScopeTree, Enabled: true},
		{ID: 2, Domain: "ok.example.com", Action: ActionAllow, Scope: ScopeTree, Enabled: true},
	}, nil, nil)
	if d := e.Decide("www.ok.example.com", Subject{}); d.Blocked {
		t.Fatalf("more specific allow should win: %+v", d)
	}
	if d := e.Decide("bad.example.com", Subject{}); !d.Blocked {
		t.Fatal("parent tree block should apply")
	}
}

func TestTreeRuleExceptionForSubdomain(t *testing.T) {
	e := engineWith([]Rule{
		{ID: 1, Domain: "example.com", Action: ActionBlock, Scope: ScopeTree, Enabled: true},
		{ID: 2, Domain: "cdn.example.com", Action: ActionAllow, Scope: ScopeExact, Enabled: true},
	}, nil, nil)
	if d := e.Decide("cdn.example.com", Subject{}); d.Blocked {
		t.Fatal("exact allow should exempt subdomain")
	}
	if d := e.Decide("www.example.com", Subject{}); !d.Blocked {
		t.Fatal("tree block should apply to other subdomains")
	}
}

func TestClientScopedRule(t *testing.T) {
	e := engineWith([]Rule{
		{ID: 1, Domain: "games.com", Action: ActionBlock, Scope: ScopeExact, ClientID: 5, Enabled: true},
	}, nil, nil)
	if d := e.Decide("games.com", Subject{ClientID: 5}); !d.Blocked {
		t.Fatal("client-scoped block should apply to that client")
	}
	if d := e.Decide("games.com", Subject{}); d.Blocked {
		t.Fatal("client-scoped block must not affect other clients")
	}
}

func TestClientScopedAllowBeatsGlobalTreeBlock(t *testing.T) {
	e := engineWith([]Rule{
		{ID: 1, Domain: "example.com", Action: ActionBlock, Scope: ScopeTree, Enabled: true},
		{ID: 2, Domain: "example.com", Action: ActionAllow, Scope: ScopeTree, ClientID: 9, Enabled: true},
	}, nil, nil)
	if d := e.Decide("www.example.com", Subject{ClientID: 9}); d.Blocked {
		t.Fatal("client-scoped rule should win at equal specificity")
	}
	if d := e.Decide("www.example.com", Subject{ClientID: 1}); !d.Blocked {
		t.Fatal("global block should apply to other clients")
	}
}

func TestDisabledRuleIgnored(t *testing.T) {
	e := engineWith([]Rule{
		{ID: 1, Domain: "a.com", Action: ActionBlock, Scope: ScopeExact, Enabled: false},
	}, nil, nil)
	if d := e.Decide("a.com", Subject{}); d.Blocked {
		t.Fatal("disabled rule must not apply")
	}
}

func TestProtectionDisabled(t *testing.T) {
	e := engineWith([]Rule{
		{ID: 1, Domain: "a.com", Action: ActionBlock, Scope: ScopeExact, Enabled: true},
	}, map[string]int64{"b.com": 1}, nil)
	e.SetProtection(false)
	for _, d := range []string{"a.com", "b.com"} {
		if dec := e.Decide(d, Subject{}); dec.Blocked || dec.Reason != ReasonProtectionDisabled {
			t.Fatalf("protection off should allow %s: %+v", d, dec)
		}
	}
	e.SetProtection(true)
	if !e.Decide("a.com", Subject{}).Blocked {
		t.Fatal("re-enabled protection should block again")
	}
}

func TestBlocklistException(t *testing.T) {
	e := engineWith(nil,
		map[string]int64{"example.com": 1},
		map[string]int64{"ok.example.com": 1})
	if d := e.Decide("ok.example.com", Subject{}); d.Blocked {
		t.Fatal("@@ exception should allow")
	}
	if d := e.Decide("www.ok.example.com", Subject{}); d.Blocked {
		t.Fatal("@@ exception covers subdomains")
	}
	if d := e.Decide("bad.example.com", Subject{}); !d.Blocked {
		t.Fatal("non-excepted subdomain stays blocked")
	}
}

// ---------- V2 ----------

func TestGroupScopedRule(t *testing.T) {
	e := engineWith([]Rule{
		{ID: 1, Domain: "tiktok.com", Action: ActionBlock, Scope: ScopeTree, GroupID: 2, Enabled: true},
	}, nil, nil)
	if d := e.Decide("www.tiktok.com", Subject{ClientID: 7, GroupID: 2}); !d.Blocked {
		t.Fatal("group rule should block group member")
	}
	if d := e.Decide("www.tiktok.com", Subject{ClientID: 8, GroupID: 3}); d.Blocked {
		t.Fatal("group rule must not affect other groups")
	}
	if d := e.Decide("www.tiktok.com", Subject{ClientID: 9}); d.Blocked {
		t.Fatal("group rule must not affect ungrouped clients")
	}
}

func TestGroupBeatsGlobalAtSameSuffix(t *testing.T) {
	e := engineWith([]Rule{
		{ID: 1, Domain: "social.com", Action: ActionBlock, Scope: ScopeTree, Enabled: true},
		{ID: 2, Domain: "social.com", Action: ActionAllow, Scope: ScopeTree, GroupID: 4, Enabled: true},
	}, nil, nil)
	if d := e.Decide("x.social.com", Subject{ClientID: 1, GroupID: 4}); d.Blocked {
		t.Fatal("group allow should win for group member")
	}
	if d := e.Decide("x.social.com", Subject{ClientID: 2, GroupID: 5}); !d.Blocked {
		t.Fatal("global block still applies outside the group")
	}
}

func TestClientBeatsGroupBeatsGlobal(t *testing.T) {
	e := engineWith([]Rule{
		{ID: 1, Domain: "d.com", Action: ActionBlock, Scope: ScopeExact, Enabled: true},
		{ID: 2, Domain: "d.com", Action: ActionAllow, Scope: ScopeExact, GroupID: 2, Enabled: true},
		{ID: 3, Domain: "d.com", Action: ActionBlock, Scope: ScopeExact, ClientID: 9, Enabled: true},
	}, nil, nil)
	if d := e.Decide("d.com", Subject{ClientID: 9, GroupID: 2}); !d.Blocked {
		t.Fatal("client block should outrank group allow")
	}
	if d := e.Decide("d.com", Subject{ClientID: 1, GroupID: 2}); d.Blocked {
		t.Fatal("group allow should outrank global block")
	}
	if d := e.Decide("d.com", Subject{ClientID: 1, GroupID: 7}); !d.Blocked {
		t.Fatal("global block applies to other groups")
	}
}

func TestGroupRestrictedBlocklist(t *testing.T) {
	e := NewEngine()
	e.Replace(Snapshot{
		Blocks: map[string]int64{"ads.com": 10, "social.com": 11},
		ListGroups: map[int64][]int64{
			11: {2}, // list 11 only applies to group 2
		},
	})
	if d := e.Decide("social.com", Subject{GroupID: 2}); !d.Blocked {
		t.Fatal("group-restricted list should block its group")
	}
	if d := e.Decide("social.com", Subject{GroupID: 9}); d.Blocked {
		t.Fatal("group-restricted list must not affect other groups")
	}
	if d := e.Decide("ads.com", Subject{GroupID: 9}); !d.Blocked {
		t.Fatal("global list blocks everyone")
	}
}

func TestScheduleProtectionOff(t *testing.T) {
	e := NewEngine()
	now := time.Date(2025, 6, 10, 21, 30, 0, 0, time.UTC) // Tuesday 21:30 UTC
	e.Replace(Snapshot{
		Blocks: map[string]int64{"ads.com": 1},
		Schedules: []schedules.Schedule{{
			ID: 1, Name: "Evening", Enabled: true, TZ: "UTC",
			DaysMask: 127, StartMin: 21 * 60, EndMin: 23 * 60,
			TargetKind: schedules.TargetGroup, TargetID: 2,
			Effect: schedules.EffectProtectionOff,
		}},
	})
	in := Subject{ClientID: 5, GroupID: 2, Now: now}
	if d := e.Decide("ads.com", in); d.Blocked || d.Reason != ReasonScheduleOff {
		t.Fatalf("schedule should suspend filtering: %+v", d)
	}
	// Outside the window it blocks again.
	if d := e.Decide("ads.com", Subject{ClientID: 5, GroupID: 2, Now: now.Add(-3 * time.Hour)}); !d.Blocked {
		t.Fatal("outside schedule window the list should block")
	}
	// Other group unaffected.
	if d := e.Decide("ads.com", Subject{ClientID: 6, GroupID: 3, Now: now}); !d.Blocked {
		t.Fatal("schedule must not affect other groups")
	}
}

func TestScheduleExtraLists(t *testing.T) {
	e := NewEngine()
	now := time.Now()
	e.Replace(Snapshot{
		Blocks: map[string]int64{"games.com": 5},
		// List 5 is not assigned to group 1 normally.
		ListGroups: map[int64][]int64{5: {9}},
		Schedules: []schedules.Schedule{{
			ID: 1, Name: "Study hours", Enabled: true, TZ: "UTC",
			DaysMask: 127, StartMin: 0, EndMin: 1439,
			TargetKind: schedules.TargetGroup, TargetID: 1,
			Effect:  schedules.EffectExtraLists,
			ListIDs: []int64{5},
		}},
	})
	if d := e.Decide("games.com", Subject{GroupID: 1, Now: now}); !d.Blocked {
		t.Fatal("scheduled extra list should block during the window")
	}
	if d := e.Decide("games.com", Subject{GroupID: 2, Now: now}); d.Blocked {
		t.Fatal("schedule must not activate the list for other groups")
	}
}

func TestExpiredRuleNotApplied(t *testing.T) {
	past := time.Now().Add(-time.Hour).Format(time.RFC3339)
	future := time.Now().Add(time.Hour).Format(time.RFC3339)
	e := engineWith([]Rule{
		{ID: 1, Domain: "old.com", Action: ActionBlock, Scope: ScopeExact, Enabled: true, ExpiresAt: past},
		{ID: 2, Domain: "temp.com", Action: ActionBlock, Scope: ScopeExact, Enabled: true, ExpiresAt: future},
	}, nil, nil)
	if d := e.Decide("old.com", Subject{}); d.Blocked {
		t.Fatal("expired rule must not apply")
	}
	if d := e.Decide("temp.com", Subject{}); !d.Blocked {
		t.Fatal("active temporary rule should apply")
	}
}

func TestExplainTraceMatchesDecide(t *testing.T) {
	e := engineWith([]Rule{
		{ID: 1, Domain: "a.com", Action: ActionBlock, Scope: ScopeExact, ClientID: 3, Enabled: true},
	}, map[string]int64{"b.com": 4}, nil)
	for _, d := range []string{"a.com", "b.com", "c.com"} {
		dec := e.Decide(d, Subject{ClientID: 3})
		ex := e.Explain(d, Subject{ClientID: 3})
		if dec.Blocked != ex.Decision.Blocked || dec.Reason != ex.Decision.Reason {
			t.Fatalf("Decide/Explain diverged for %s: %+v vs %+v", d, dec, ex.Decision)
		}
		if len(ex.Steps) == 0 {
			t.Fatal("explain must produce a trace")
		}
		last := ex.Steps[len(ex.Steps)-1]
		if !last.Matched {
			t.Fatalf("last step should be the matched stage, got %+v", last)
		}
	}
}

func TestMatchAllAndDomainSources(t *testing.T) {
	e := engineWith([]Rule{
		{ID: 1, Domain: "a.com", Action: ActionBlock, Scope: ScopeTree, Enabled: true},
		{ID: 2, Domain: "x.a.com", Action: ActionAllow, Scope: ScopeExact, Enabled: true},
	}, map[string]int64{"deep.a.com": 3}, nil)
	rules := e.MatchAll("www.deep.a.com", Subject{})
	if len(rules) != 1 { // only tree a.com matches
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	blocks, allows := e.DomainSources("www.deep.a.com")
	if len(blocks) != 1 || blocks[3] != "deep.a.com" {
		t.Fatalf("expected list 3, got %v", blocks)
	}
	if len(allows) != 0 {
		t.Fatalf("unexpected exceptions %v", allows)
	}
}
