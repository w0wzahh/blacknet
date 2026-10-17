package filtering

import "testing"

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
	e.Replace(rules, blocks, allows)
	return e
}

func TestPrecedenceExactAllowBeatsBlock(t *testing.T) {
	e := engineWith([]Rule{
		{ID: 1, Domain: "a.com", Action: ActionAllow, Scope: ScopeExact, Enabled: true},
		{ID: 2, Domain: "a.com", Action: ActionBlock, Scope: ScopeExact, Enabled: true},
	}, nil, nil)
	d := e.Decide("a.com", 0)
	if d.Blocked || d.Reason != ReasonAllowedExact {
		t.Fatalf("got %+v", d)
	}
}

func TestAllowOverridesBlocklist(t *testing.T) {
	e := engineWith([]Rule{
		{ID: 1, Domain: "ads.com", Action: ActionAllow, Scope: ScopeExact, Enabled: true},
	}, map[string]int64{"ads.com": 7}, nil)
	d := e.Decide("ads.com", 0)
	if d.Blocked {
		t.Fatalf("allow rule should override blocklist, got %+v", d)
	}
}

func TestBlocklistBlocksSubdomains(t *testing.T) {
	e := engineWith(nil, map[string]int64{"ads.com": 3}, nil)
	for _, d := range []string{"ads.com", "www.ads.com", "deep.www.ads.com"} {
		dec := e.Decide(d, 0)
		if !dec.Blocked || dec.ListID != 3 {
			t.Fatalf("domain %s not blocked: %+v", d, dec)
		}
	}
	if e.Decide("notads.com", 0).Blocked {
		t.Fatal("notads.com should not be blocked")
	}
	if e.Decide("ads.com.evil.com", 0).Blocked {
		t.Fatal("suffix spoof should not match")
	}
}

func TestTreeRuleMoreSpecificWins(t *testing.T) {
	e := engineWith([]Rule{
		{ID: 1, Domain: "example.com", Action: ActionBlock, Scope: ScopeTree, Enabled: true},
		{ID: 2, Domain: "ok.example.com", Action: ActionAllow, Scope: ScopeTree, Enabled: true},
	}, nil, nil)
	if d := e.Decide("www.ok.example.com", 0); d.Blocked {
		t.Fatalf("more specific allow should win: %+v", d)
	}
	if d := e.Decide("bad.example.com", 0); !d.Blocked {
		t.Fatal("parent tree block should apply")
	}
}

func TestTreeRuleExceptionForSubdomain(t *testing.T) {
	e := engineWith([]Rule{
		{ID: 1, Domain: "example.com", Action: ActionBlock, Scope: ScopeTree, Enabled: true},
		{ID: 2, Domain: "cdn.example.com", Action: ActionAllow, Scope: ScopeExact, Enabled: true},
	}, nil, nil)
	if d := e.Decide("cdn.example.com", 0); d.Blocked {
		t.Fatal("exact allow should exempt subdomain")
	}
	if d := e.Decide("www.example.com", 0); !d.Blocked {
		t.Fatal("tree block should apply to other subdomains")
	}
}

func TestClientScopedRule(t *testing.T) {
	e := engineWith([]Rule{
		{ID: 1, Domain: "games.com", Action: ActionBlock, Scope: ScopeExact, ClientID: 5, Enabled: true},
	}, nil, nil)
	if d := e.Decide("games.com", 5); !d.Blocked {
		t.Fatal("client-scoped block should apply to that client")
	}
	if d := e.Decide("games.com", 0); d.Blocked {
		t.Fatal("client-scoped block must not affect other clients")
	}
}

func TestClientScopedAllowBeatsGlobalTreeBlock(t *testing.T) {
	e := engineWith([]Rule{
		{ID: 1, Domain: "example.com", Action: ActionBlock, Scope: ScopeTree, Enabled: true},
		{ID: 2, Domain: "example.com", Action: ActionAllow, Scope: ScopeTree, ClientID: 9, Enabled: true},
	}, nil, nil)
	if d := e.Decide("www.example.com", 9); d.Blocked {
		t.Fatal("client-scoped rule should win at equal specificity")
	}
	if d := e.Decide("www.example.com", 1); !d.Blocked {
		t.Fatal("global block should apply to other clients")
	}
}

func TestDisabledRuleIgnored(t *testing.T) {
	e := engineWith([]Rule{
		{ID: 1, Domain: "a.com", Action: ActionBlock, Scope: ScopeExact, Enabled: false},
	}, nil, nil)
	if d := e.Decide("a.com", 0); d.Blocked {
		t.Fatal("disabled rule must not apply")
	}
}

func TestProtectionDisabled(t *testing.T) {
	e := engineWith([]Rule{
		{ID: 1, Domain: "a.com", Action: ActionBlock, Scope: ScopeExact, Enabled: true},
	}, map[string]int64{"b.com": 1}, nil)
	e.SetProtection(false)
	for _, d := range []string{"a.com", "b.com"} {
		if dec := e.Decide(d, 0); dec.Blocked || dec.Reason != ReasonProtectionDisabled {
			t.Fatalf("protection off should allow %s: %+v", d, dec)
		}
	}
	e.SetProtection(true)
	if !e.Decide("a.com", 0).Blocked {
		t.Fatal("re-enabled protection should block again")
	}
}

func TestBlocklistException(t *testing.T) {
	e := engineWith(nil,
		map[string]int64{"example.com": 1},
		map[string]int64{"ok.example.com": 1})
	if d := e.Decide("ok.example.com", 0); d.Blocked {
		t.Fatal("@@ exception should allow")
	}
	if d := e.Decide("www.ok.example.com", 0); d.Blocked {
		t.Fatal("@@ exception covers subdomains")
	}
	if d := e.Decide("bad.example.com", 0); !d.Blocked {
		t.Fatal("non-excepted subdomain stays blocked")
	}
}
