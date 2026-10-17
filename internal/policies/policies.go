// Package policies implements policy groups and subject resolution.
//
// A policy group is a named filter profile: an optional upstream override, a
// set of scoped blocklists and rules. Clients join a group directly, by
// source IP, or by CIDR. Resolution order (documented in
// docs/policy-groups.md):
//
//	client assignment > single-IP assignment > longest CIDR > default (0)
//
// Group 0 is the implicit "default" group for unassigned clients and uses
// only global rules and global lists.
package policies

import (
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
)

// Assignment kinds stored in policy_assignments.
const (
	KindClient = "client"
	KindIP     = "ip"
	KindCIDR   = "cidr"
)

// Group is a filter profile.
type Group struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Enabled     bool   `json:"enabled"`
	// UpstreamID forces group members' forwarded queries through one
	// configured upstream resolver; 0 = use the normal pool.
	UpstreamID int64  `json:"upstream_id"`
	CreatedAt  string `json:"created_at"`
	UpdatedAt  string `json:"updated_at"`
	// ClientCount/ListIDs are populated by list endpoints, not stored.
	ClientCount int     `json:"client_count,omitempty"`
	ListIDs     []int64 `json:"list_ids,omitempty"`
}

// Validate checks a group before insert/update.
func (g *Group) Validate() map[string]string {
	errs := map[string]string{}
	g.Name = strings.TrimSpace(g.Name)
	if g.Name == "" {
		errs["name"] = "name is required"
	} else if len(g.Name) > 60 {
		errs["name"] = "name too long"
	}
	if len(g.Description) > 300 {
		errs["description"] = "description too long"
	}
	return errs
}

// Assignment binds an IP or CIDR to a group.
type Assignment struct {
	ID        int64  `json:"id"`
	Kind      string `json:"kind"`
	Value     string `json:"value"`
	GroupID   int64  `json:"group_id"`
	GroupName string `json:"group_name,omitempty"`
	CreatedAt string `json:"created_at"`
}

// Validate checks the kind/value pair.
func (a *Assignment) Validate() map[string]string {
	errs := map[string]string{}
	switch a.Kind {
	case KindClient:
		id, err := strconv.ParseInt(strings.TrimSpace(a.Value), 10, 64)
		if err != nil || id <= 0 {
			errs["value"] = "expected a client id"
		} else {
			a.Value = strconv.FormatInt(id, 10)
		}
	case KindIP:
		ip, err := netip.ParseAddr(strings.TrimSpace(a.Value))
		if err != nil {
			errs["value"] = "expected an IP address"
		} else {
			a.Value = ip.String()
		}
	case KindCIDR:
		p, err := netip.ParsePrefix(strings.TrimSpace(a.Value))
		if err != nil {
			errs["value"] = "expected a CIDR like 192.168.1.0/24"
		} else {
			a.Value = p.Masked().String()
		}
	default:
		errs["kind"] = "kind must be client, ip or cidr"
	}
	if a.GroupID <= 0 {
		errs["group_id"] = "a target group is required"
	}
	return errs
}

// Describe returns a human-readable target for logs/audit.
func (a *Assignment) Describe() string {
	return fmt.Sprintf("%s %s -> group %s", a.Kind, a.Value, strconv.FormatInt(a.GroupID, 10))
}

// Resolver is an immutable snapshot mapping subjects to groups. Rebuilt on
// every policy change; DNS queries read it without locks.
type Resolver struct {
	clientGroup  map[int64]int64 // clients.policy_group_id
	clientAssign map[int64]int64 // explicit kind=client assignments (win over table)
	ipMap        map[string]int64
	cidrs        []cidrAssign // sorted longest prefix first
	groups       map[int64]Group
}

type cidrAssign struct {
	prefix  netip.Prefix
	groupID int64
}

// NewResolver builds a snapshot. clientGroups maps client_id -> group_id
// (from the clients table); assigns are ip/cidr rows; groups is all groups.
func NewResolver(clientGroups map[int64]int64, assigns []Assignment, groups []Group) *Resolver {
	r := &Resolver{
		clientGroup:  clientGroups,
		clientAssign: map[int64]int64{},
		ipMap:        map[string]int64{},
		groups:       map[int64]Group{},
	}
	for _, g := range groups {
		r.groups[g.ID] = g
	}
	for _, a := range assigns {
		switch a.Kind {
		case KindClient:
			if id, err := strconv.ParseInt(a.Value, 10, 64); err == nil {
				r.clientAssign[id] = a.GroupID
			}
		case KindIP:
			r.ipMap[a.Value] = a.GroupID
		case KindCIDR:
			if p, err := netip.ParsePrefix(a.Value); err == nil {
				r.cidrs = append(r.cidrs, cidrAssign{p.Masked(), a.GroupID})
			}
		}
	}
	sort.Slice(r.cidrs, func(i, j int) bool {
		return r.cidrs[i].prefix.Bits() > r.cidrs[j].prefix.Bits()
	})
	return r
}

// GroupFor resolves the effective group for a source address / client id.
func (r *Resolver) GroupFor(ip netip.Addr, clientID int64) int64 {
	if r == nil {
		return 0
	}
	if gid, ok := r.clientAssign[clientID]; ok && gid != 0 {
		return gid
	}
	if gid, ok := r.clientGroup[clientID]; ok && gid != 0 {
		return gid
	}
	if gid, ok := r.ipMap[ip.String()]; ok {
		return gid
	}
	for _, c := range r.cidrs {
		if c.prefix.Contains(ip) {
			return c.groupID
		}
	}
	return 0
}

// Group returns the group definition, ok=false when unknown.
func (r *Resolver) Group(id int64) (Group, bool) {
	if r == nil {
		return Group{}, false
	}
	g, ok := r.groups[id]
	return g, ok
}

// Groups returns every group.
func (r *Resolver) Groups() []Group {
	if r == nil {
		return nil
	}
	out := make([]Group, 0, len(r.groups))
	for _, g := range r.groups {
		out = append(out, g)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// UpstreamFor returns the upstream override for a group, 0 when none.
func (r *Resolver) UpstreamFor(groupID int64) int64 {
	g, ok := r.Group(groupID)
	if !ok || !g.Enabled {
		return 0
	}
	return g.UpstreamID
}

// DisabledGroups returns the set of disabled group ids (engine skips their
// rules and restricted lists).
func (r *Resolver) DisabledGroups() map[int64]bool {
	out := map[int64]bool{}
	for _, g := range r.Groups() {
		if !g.Enabled {
			out[g.ID] = true
		}
	}
	return out
}
