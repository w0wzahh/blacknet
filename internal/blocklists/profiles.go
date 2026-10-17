package blocklists

import (
	"context"
	"fmt"
)

// Profile is a curated bundle of verified blocklist sources.
type Profile struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Risk        string   `json:"risk"` // low | medium | high (false-positive likelihood)
	Lists       []Source `json:"lists"`
}

// Source is a catalogued blocklist.
type Source struct {
	Name string `json:"name"`
	URL  string `json:"url"`
}

// Catalog of verified, maintained sources. Applying a profile enables the
// listed sources and adds any that are missing; existing custom lists are
// left enabled (a profile is additive by design).
var Catalog = []Profile{
	{
		ID:          "minimal",
		Name:        "Minimal",
		Description: "StevenBlack's unified hosts file — ads and malware, very low false-positive rate.",
		Risk:        "low",
		Lists: []Source{
			{Name: "StevenBlack Unified Hosts", URL: "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"},
		},
	},
	{
		ID:          "balanced",
		Name:        "Balanced (default)",
		Description: "StevenBlack hosts plus AdGuard's DNS filter — broad ad/tracker coverage with moderate size.",
		Risk:        "low",
		Lists: []Source{
			{Name: "StevenBlack Unified Hosts", URL: "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"},
			{Name: "AdGuard DNS Filter", URL: "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt"},
		},
	},
	{
		ID:          "strict",
		Name:        "Strict",
		Description: "Balanced plus OISD Big — aggressive coverage; some legitimate services may be blocked (use exceptions).",
		Risk:        "medium",
		Lists: []Source{
			{Name: "StevenBlack Unified Hosts", URL: "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"},
			{Name: "AdGuard DNS Filter", URL: "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt"},
			{Name: "OISD Big", URL: "https://big.oisd.nl"},
		},
	},
}

// GetProfile returns a catalog entry.
func GetProfile(id string) (*Profile, bool) {
	for i := range Catalog {
		if Catalog[i].ID == id {
			return &Catalog[i], true
		}
	}
	return nil, false
}

// ApplyProfile ensures every source in the profile exists and is enabled.
// Returns the list ids now covered by the profile. Caller should refresh.
func (m *Manager) ApplyProfile(ctx context.Context, profileID string) ([]int64, error) {
	p, ok := GetProfile(profileID)
	if !ok {
		return nil, fmt.Errorf("unknown profile %q", profileID)
	}
	existing, err := m.db.ListBlocklists(ctx)
	if err != nil {
		return nil, err
	}
	byURL := map[string]int64{}
	for _, b := range existing {
		byURL[b.URL] = b.ID
	}
	var ids []int64
	for _, src := range p.Lists {
		id, ok := byURL[src.URL]
		if !ok {
			bl, err := m.db.AddBlocklist(ctx, src.Name, src.URL)
			if err != nil {
				return ids, err
			}
			id = bl.ID
		}
		if err := m.db.SetBlocklistEnabled(ctx, id, true); err != nil {
			return ids, err
		}
		ids = append(ids, id)
	}
	return ids, nil
}

// ListDomains loads one list's domain set (blocks only) for analysis.
func (m *Manager) ListDomains(ctx context.Context, id int64) (map[string]struct{}, error) {
	return m.db.ListDomains(ctx, id)
}
