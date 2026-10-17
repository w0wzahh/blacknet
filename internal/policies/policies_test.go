package policies

import (
	"net/netip"
	"testing"
)

func TestResolverMostSpecificWins(t *testing.T) {
	groups := []Group{
		{ID: 1, Name: "kids", Enabled: true},
		{ID: 2, Name: "iot", Enabled: true},
		{ID: 3, Name: "off", Enabled: false},
	}
	assigns := []Assignment{
		{Kind: "cidr", Value: "10.0.0.0/8", GroupID: 2},
		{Kind: "ip", Value: "10.0.0.5", GroupID: 1},
		{Kind: "client", Value: "7", GroupID: 3},
	}
	r := NewResolver(map[int64]int64{7: 3}, assigns, groups)

	ip := netip.MustParseAddr("10.0.0.5")
	// Exact IP assignment beats the covering CIDR.
	if got := r.GroupFor(ip, 0); got != 1 {
		t.Fatalf("expected group 1, got %d", got)
	}
	// CIDR applies to other addresses in range.
	if got := r.GroupFor(netip.MustParseAddr("10.0.0.99"), 0); got != 2 {
		t.Fatalf("expected group 2, got %d", got)
	}
	// No match → 0 (default policy).
	if got := r.GroupFor(netip.MustParseAddr("192.168.1.1"), 0); got != 0 {
		t.Fatalf("expected 0, got %d", got)
	}
	// Stable client id assignment.
	if got := r.GroupFor(netip.MustParseAddr("9.9.9.9"), 7); got != 3 {
		t.Fatalf("expected group 3 for client 7, got %d", got)
	}
	// Disabled group is reported disabled.
	if !r.DisabledGroups()[3] {
		t.Fatal("group 3 should be marked disabled")
	}
	if r.DisabledGroups()[1] {
		t.Fatal("group 1 should not be disabled")
	}
}

func TestResolverUpstreamOverride(t *testing.T) {
	groups := []Group{
		{ID: 1, Name: "kids", UpstreamID: 9, Enabled: true},
		{ID: 2, Name: "paused", UpstreamID: 9, Enabled: false},
	}
	r := NewResolver(nil, nil, groups)
	if got := r.UpstreamFor(1); got != 9 {
		t.Fatalf("expected upstream 9, got %d", got)
	}
	if got := r.UpstreamFor(0); got != 0 {
		t.Fatalf("expected 0 for default, got %d", got)
	}
	// A disabled group's upstream override must not apply.
	if got := r.UpstreamFor(2); got != 0 {
		t.Fatalf("disabled group should not override upstream, got %d", got)
	}
}
