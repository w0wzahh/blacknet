// Package settings defines Blacknet's runtime-editable, persisted settings.
package settings

import (
	"context"
	"encoding/json"

	"github.com/emre/blacknet/internal/database"
)

// Settings are runtime-editable application settings persisted in SQLite.
type Settings struct {
	ProtectionEnabled      bool   `json:"protection_enabled"`
	BlockingMode           string `json:"blocking_mode"` // nxdomain | null
	CacheEnabled           bool   `json:"cache_enabled"`
	CacheMaxEntries        int    `json:"cache_max_entries"`
	CacheMinTTLSeconds     int    `json:"cache_min_ttl_seconds"`
	CacheMaxTTLSeconds     int    `json:"cache_max_ttl_seconds"`
	BlocklistRefreshHours  int    `json:"blocklist_refresh_hours"`
	QueryRetentionDays     int    `json:"query_retention_days"`
	ParallelUpstreams      bool   `json:"parallel_upstreams"`
	AllowPrivateLists      bool   `json:"allow_private_lists"`
	HealthProbeDomain      string `json:"health_probe_domain"`
	HealthProbeIntervalSec int    `json:"health_probe_interval_seconds"`
	SetupCompleted         bool   `json:"setup_completed"`
}

// Default returns safe defaults.
func Default() Settings {
	return Settings{
		ProtectionEnabled:      true,
		BlockingMode:           "nxdomain",
		CacheEnabled:           true,
		CacheMaxEntries:        10000,
		CacheMinTTLSeconds:     0,
		CacheMaxTTLSeconds:     86400,
		BlocklistRefreshHours:  24,
		QueryRetentionDays:     30,
		ParallelUpstreams:      false,
		AllowPrivateLists:      false,
		HealthProbeDomain:      "example.com",
		HealthProbeIntervalSec: 60,
	}
}

// LoadSettings reads persisted settings over the defaults.
func Load(ctx context.Context, db *database.DB) (Settings, error) {
	s := Default()
	all, err := db.AllSettings()
	if err != nil {
		return s, err
	}
	decode := func(key string, out any) {
		if raw, ok := all["settings."+key]; ok {
			_ = json.Unmarshal(raw, out)
		}
	}
	decode("protection_enabled", &s.ProtectionEnabled)
	decode("blocking_mode", &s.BlockingMode)
	decode("cache_enabled", &s.CacheEnabled)
	decode("cache_max_entries", &s.CacheMaxEntries)
	decode("cache_min_ttl_seconds", &s.CacheMinTTLSeconds)
	decode("cache_max_ttl_seconds", &s.CacheMaxTTLSeconds)
	decode("blocklist_refresh_hours", &s.BlocklistRefreshHours)
	decode("query_retention_days", &s.QueryRetentionDays)
	decode("parallel_upstreams", &s.ParallelUpstreams)
	decode("allow_private_lists", &s.AllowPrivateLists)
	decode("health_probe_domain", &s.HealthProbeDomain)
	decode("health_probe_interval_seconds", &s.HealthProbeIntervalSec)
	decode("setup_completed", &s.SetupCompleted)
	return s, nil
}

// Save persists a single settings key.
func Save(ctx context.Context, db *database.DB, key string, v any) error {
	return db.SetSetting("settings."+key, v)
}

// Validate checks a settings patch for sane values.
func Validate(s *Settings) map[string]string {
	errs := map[string]string{}
	if s.BlockingMode != "nxdomain" && s.BlockingMode != "null" {
		errs["blocking_mode"] = "must be 'nxdomain' or 'null'"
	}
	if s.CacheMaxEntries < 0 || s.CacheMaxEntries > 1_000_000 {
		errs["cache_max_entries"] = "must be between 0 and 1000000"
	}
	if s.CacheMinTTLSeconds < 0 || s.CacheMinTTLSeconds > 86400 {
		errs["cache_min_ttl_seconds"] = "must be between 0 and 86400"
	}
	if s.CacheMaxTTLSeconds < 60 || s.CacheMaxTTLSeconds > 7*86400 {
		errs["cache_max_ttl_seconds"] = "must be between 60 and 604800"
	}
	if s.CacheMinTTLSeconds > s.CacheMaxTTLSeconds {
		errs["cache_min_ttl_seconds"] = "must not exceed cache_max_ttl_seconds"
	}
	if s.BlocklistRefreshHours < 1 || s.BlocklistRefreshHours > 24*30 {
		errs["blocklist_refresh_hours"] = "must be between 1 and 720"
	}
	if s.QueryRetentionDays < 1 || s.QueryRetentionDays > 365 {
		errs["query_retention_days"] = "must be between 1 and 365"
	}
	if s.HealthProbeIntervalSec < 0 || s.HealthProbeIntervalSec > 86400 {
		errs["health_probe_interval_seconds"] = "must be between 0 and 86400"
	}
	return errs
}
