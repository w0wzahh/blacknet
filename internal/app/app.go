// Package app wires together the DNS server, filtering engine, persistence,
// upstream pool, blocklist manager and background schedulers.
package app

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/w0wzahh/blacknet/internal/blocklists"
	"github.com/w0wzahh/blacknet/internal/cache"
	"github.com/w0wzahh/blacknet/internal/config"
	"github.com/w0wzahh/blacknet/internal/database"
	"github.com/w0wzahh/blacknet/internal/dhcp"
	"github.com/w0wzahh/blacknet/internal/dnsserver"
	"github.com/w0wzahh/blacknet/internal/events"
	"github.com/w0wzahh/blacknet/internal/filtering"
	"github.com/w0wzahh/blacknet/internal/settings"
	"github.com/w0wzahh/blacknet/internal/upstream"
)

// Version is set by main at build time.
var Version = "1.0.0-dev"

// App is the composed application.
type App struct {
	Cfg    *config.Config
	DB     *database.DB
	Engine *filtering.Engine
	Pool   *upstream.Pool
	Cache  *cache.Cache
	Lists  *blocklists.Manager
	Bus    *events.Bus[dnsserver.QueryEvent]
	QLog   *database.QueryLogger
	DNS    *dnsserver.Server

	dhcpMu  sync.Mutex
	dhcpSrv *dhcp.Server

	settingsMu sync.RWMutex
	settings   settings.Settings

	schedCancel context.CancelFunc
	log         *slog.Logger
}

// New builds the application: opens the DB, seeds defaults, and constructs
// every component. Nothing listens until Start is called.
func New(cfg *config.Config) (*App, error) {
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
	}
	db, err := database.Open(cfg.DBPath())
	if err != nil {
		return nil, err
	}
	a := &App{
		Cfg:    cfg,
		DB:     db,
		Engine: filtering.NewEngine(),
		Bus:    events.New[dnsserver.QueryEvent](),
		log:    slog.Default(),
	}
	if err := a.seed(context.Background()); err != nil {
		db.Close()
		return nil, err
	}
	settings, err := settings.Load(context.Background(), db)
	if err != nil {
		db.Close()
		return nil, err
	}
	a.settings = settings

	a.Cache = cache.New(settings.CacheMaxEntries,
		time.Duration(settings.CacheMinTTLSeconds)*time.Second,
		time.Duration(settings.CacheMaxTTLSeconds)*time.Second,
		60*time.Second)
	a.Cache.SetEnabled(settings.CacheEnabled)

	pool, err := a.buildPool(context.Background())
	if err != nil {
		a.log.Warn("upstream pool init", "err", err)
	}
	a.Pool = pool

	a.QLog = database.NewQueryLogger(db, 8192)

	a.Lists = blocklists.NewManager(db, settings.AllowPrivateLists, func() {
		if err := a.ReloadRules(context.Background()); err != nil {
			a.log.Error("reload after blocklist refresh failed", "err", err)
		}
	})

	trusted, err := cfg.TrustedPrefixes()
	if err != nil {
		db.Close()
		return nil, err
	}
	a.DNS = dnsserver.New(dnsserver.Options{
		Addrs:    cfg.DNS.Listen,
		Trusted:  trusted,
		Engine:   a.Engine,
		Upstream: a.Pool,
		Cache:    a.Cache,
		Publish:  a.publishEvent,
		LookupClient: func(ip netip.Addr) int64 {
			return a.QLog.LookupClient(ip)
		},
	})
	a.applySettings(settings)

	if err := a.ReloadRules(context.Background()); err != nil {
		db.Close()
		return nil, err
	}
	return a, nil
}

func (a *App) publishEvent(ev dnsserver.QueryEvent) {
	a.QLog.Submit(ev)
	a.Bus.Publish(ev)
}

// seed inserts first-run defaults (settings, upstreams, blocklists).
func (a *App) seed(ctx context.Context) error {
	var seeded bool
	exists, err := a.DB.GetSetting("meta.seeded", &seeded)
	if err != nil {
		return err
	}
	if exists && seeded {
		return nil
	}
	// Default upstreams (plain DNS to well-known public resolvers; users can
	// change protocol/provider in the dashboard).
	ups, err := a.DB.ListUpstreams(ctx)
	if err != nil {
		return err
	}
	if len(ups) == 0 {
		for _, u := range []upstream.Config{
			{Name: "Cloudflare", Protocol: upstream.ProtoUDP, Address: "1.1.1.1:53", Priority: 0, Timeout: 4 * time.Second, Enabled: true},
			{Name: "Quad9", Protocol: upstream.ProtoUDP, Address: "9.9.9.9:53", Priority: 1, Timeout: 4 * time.Second, Enabled: true},
		} {
			u := u
			if err := a.DB.AddUpstream(ctx, &u); err != nil {
				return err
			}
		}
	}
	lists, err := a.DB.ListBlocklists(ctx)
	if err != nil {
		return err
	}
	if len(lists) == 0 {
		for _, src := range []struct{ name, url string }{
			{"StevenBlack Unified Hosts", "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"},
			{"AdGuard DNS Filter", "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt"},
		} {
			if _, err := a.DB.AddBlocklist(ctx, src.name, src.url); err != nil {
				return err
			}
		}
	}
	for k, v := range map[string]any{
		"protection_enabled":            true,
		"blocking_mode":                 "nxdomain",
		"cache_enabled":                 true,
		"cache_max_entries":             10000,
		"cache_min_ttl_seconds":         0,
		"cache_max_ttl_seconds":         86400,
		"blocklist_refresh_hours":       24,
		"query_retention_days":          30,
		"parallel_upstreams":            false,
		"allow_private_lists":           false,
		"health_probe_domain":           "example.com",
		"health_probe_interval_seconds": 60,
		"setup_completed":               false,
	} {
		if err := settings.Save(ctx, a.DB, k, v); err != nil {
			return err
		}
	}
	return a.DB.SetSetting("meta.seeded", true)
}

// GetSettings returns the current settings snapshot.
func (a *App) GetSettings() settings.Settings {
	a.settingsMu.RLock()
	defer a.settingsMu.RUnlock()
	return a.settings
}

// UpdateSettings validates and persists a patch, then applies it live.
func (a *App) UpdateSettings(ctx context.Context, patch map[string]json.RawMessage) (settings.Settings, map[string]string, error) {
	a.settingsMu.Lock()
	s := a.settings
	a.settingsMu.Unlock()
	// Apply patch fields.
	m := map[string]*json.RawMessage{}
	for k, v := range patch {
		v := v
		m[k] = &v
	}
	type f struct {
		key string
		ptr any
	}
	fields := []f{
		{"protection_enabled", &s.ProtectionEnabled},
		{"blocking_mode", &s.BlockingMode},
		{"cache_enabled", &s.CacheEnabled},
		{"cache_max_entries", &s.CacheMaxEntries},
		{"cache_min_ttl_seconds", &s.CacheMinTTLSeconds},
		{"cache_max_ttl_seconds", &s.CacheMaxTTLSeconds},
		{"blocklist_refresh_hours", &s.BlocklistRefreshHours},
		{"query_retention_days", &s.QueryRetentionDays},
		{"parallel_upstreams", &s.ParallelUpstreams},
		{"allow_private_lists", &s.AllowPrivateLists},
		{"health_probe_domain", &s.HealthProbeDomain},
		{"health_probe_interval_seconds", &s.HealthProbeIntervalSec},
		{"setup_completed", &s.SetupCompleted},
	}
	errs := map[string]string{}
	for _, fld := range fields {
		if raw, ok := m[fld.key]; ok {
			if err := json.Unmarshal(*raw, fld.ptr); err != nil {
				errs[fld.key] = "invalid value"
			}
		}
	}
	if verr := settings.Validate(&s); len(verr) > 0 {
		for k, v := range verr {
			errs[k] = v
		}
	}
	if len(errs) > 0 {
		return a.GetSettings(), errs, nil
	}
	for _, fld := range fields {
		if _, ok := m[fld.key]; ok {
			var v any
			raw := m[fld.key]
			_ = json.Unmarshal(*raw, &v)
			if err := settings.Save(ctx, a.DB, fld.key, v); err != nil {
				return a.GetSettings(), nil, err
			}
		}
	}
	a.settingsMu.Lock()
	a.settings = s
	a.settingsMu.Unlock()
	a.applySettings(s)
	return s, nil, nil
}

// applySettings pushes settings into live components.
func (a *App) applySettings(s settings.Settings) {
	a.Engine.SetProtection(s.ProtectionEnabled)
	if a.DNS != nil {
		_ = a.DNS.SetBlockingMode(s.BlockingMode)
	}
	if a.Cache != nil {
		a.Cache.SetEnabled(s.CacheEnabled)
	}
}

func (a *App) buildPool(ctx context.Context) (*upstream.Pool, error) {
	cfgs, err := a.DB.ListUpstreams(ctx)
	if err != nil {
		return nil, err
	}
	return upstream.NewPool(cfgs, a.settings.ParallelUpstreams)
}

// ReloadUpstreams rebuilds the resolver pool from the database.
func (a *App) ReloadUpstreams(ctx context.Context) error {
	cfgs, err := a.DB.ListUpstreams(ctx)
	if err != nil {
		return err
	}
	return a.Pool.SetResolvers(cfgs, a.settings.ParallelUpstreams)
}

// ReloadRules rebuilds the filtering engine from rules + enabled blocklists.
func (a *App) ReloadRules(ctx context.Context) error {
	rules, err := a.DB.ListRules(ctx)
	if err != nil {
		return err
	}
	blocks, allows, err := a.DB.ImportedDomains(ctx)
	if err != nil {
		return err
	}
	a.Engine.Replace(rules, blocks, allows)
	return nil
}

// leaseStore adapts *database.DB to dhcp.LeaseStore.
type leaseStore struct{ db *database.DB }

func (l leaseStore) LoadLeases(ctx context.Context) ([]dhcp.Lease, error) {
	rows, err := l.db.LoadLeases(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]dhcp.Lease, 0, len(rows))
	for _, r := range rows {
		out = append(out, dhcp.Lease{MAC: r.MAC, IP: r.IP, Hostname: r.Hostname, ExpiresAt: r.ExpiresAt})
	}
	return out, nil
}
func (l leaseStore) SaveLease(ctx context.Context, lease dhcp.Lease) error {
	return l.db.SaveLease(ctx, lease.MAC, lease.IP, lease.Hostname, lease.ExpiresAt)
}
func (l leaseStore) DeleteLease(ctx context.Context, mac string) error {
	return l.db.DeleteLease(ctx, mac)
}

// ---------- DHCP (Mode B, opt-in) ----------

// GetDHCP returns the current DHCP config and whether the server is running.
func (a *App) GetDHCP(ctx context.Context) (dhcp.Config, bool, []dhcp.Lease, error) {
	var cfg dhcp.Config
	if _, err := a.DB.GetSetting("dhcp.config", &cfg); err != nil {
		return cfg, false, nil, err
	}
	a.dhcpMu.Lock()
	srv := a.dhcpSrv
	a.dhcpMu.Unlock()
	leases := []dhcp.Lease{}
	if srv != nil {
		leases = srv.Leases()
	}
	return cfg, srv != nil, leases, nil
}

// SetDHCP validates and stores config. When cfg.Enabled the server starts —
// refusing if the interface IP is wrong or validation fails.
// wantAckExistingServer should be true only when the user acknowledged the
// "another DHCP server detected" warning.
func (a *App) SetDHCP(ctx context.Context, cfg dhcp.Config, ackOtherServer bool) (map[string]string, error) {
	problems := map[string]string{}
	if cfg.Enabled {
		if err := cfg.Validate(); err != nil {
			problems["config"] = err.Error()
		} else {
			// Warn about a competing DHCP server unless acknowledged.
			if !ackOtherServer {
				other, err := dhcp.DetectOtherServers(ctx, cfg.InterfaceIP)
				if err != nil {
					problems["detect"] = "could not probe for existing DHCP servers: " + err.Error()
				} else if other {
					problems["conflict"] = "another DHCP server answered on this LAN; disable it first or re-submit with acknowledge_conflict=true"
				}
			}
		}
	}
	if len(problems) > 0 {
		return problems, nil
	}
	a.dhcpMu.Lock()
	if a.dhcpSrv != nil {
		a.dhcpSrv.Stop()
		a.dhcpSrv = nil
	}
	if cfg.Enabled {
		srv, err := dhcp.New(cfg, leaseStore{a.DB})
		if err != nil {
			a.dhcpMu.Unlock()
			return map[string]string{"config": err.Error()}, nil
		}
		if err := srv.Start(ctx); err != nil {
			a.dhcpMu.Unlock()
			return map[string]string{"config": err.Error()}, nil
		}
		a.dhcpSrv = srv
	}
	a.dhcpMu.Unlock()
	if err := a.DB.SetSetting("dhcp.config", cfg); err != nil {
		return nil, err
	}
	a.DB.Audit(ctx, "dhcp.config", fmt.Sprintf("enabled=%t", cfg.Enabled))
	return nil, nil
}

// APIToken returns the local CLI token, generating it on first use.
func (a *App) APIToken() (string, error) {
	path := a.Cfg.TokenPath()
	if raw, err := os.ReadFile(path); err == nil && len(raw) >= 32 {
		return string(raw), nil
	}
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	tok := hex.EncodeToString(buf)
	if err := os.WriteFile(path, []byte(tok), 0o600); err != nil {
		return "", err
	}
	return tok, nil
}

// Start launches the query writer, DNS listeners and schedulers.
func (a *App) Start(ctx context.Context) error {
	a.QLog.Start(ctx)
	if err := a.DNS.Start(); err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(ctx)
	a.schedCancel = cancel
	go a.refreshLoop(ctx)
	go a.retentionLoop(ctx)
	go a.healthLoop(ctx)
	return nil
}

// Shutdown stops schedulers, DNS listeners and the query writer.
func (a *App) Shutdown(ctx context.Context) {
	if a.schedCancel != nil {
		a.schedCancel()
	}
	if a.DNS != nil {
		_ = a.DNS.Shutdown(ctx)
	}
	if a.QLog != nil {
		a.QLog.Stop()
	}
	a.dhcpMu.Lock()
	if a.dhcpSrv != nil {
		a.dhcpSrv.Stop()
		a.dhcpSrv = nil
	}
	a.dhcpMu.Unlock()
	if a.DB != nil {
		a.DB.Close()
	}
}

func (a *App) refreshLoop(ctx context.Context) {
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			interval := time.Duration(a.GetSettings().BlocklistRefreshHours) * time.Hour
			res := a.Lists.RefreshAll(ctx, interval)
			for _, r := range res {
				a.log.Info("blocklist refresh", "list", r.ListID, "msg", r.Message)
			}
		}
	}
}

func (a *App) retentionLoop(ctx context.Context) {
	t := time.NewTicker(6 * time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			days := a.GetSettings().QueryRetentionDays
			cutoff := time.Now().Add(-time.Duration(days) * 24 * time.Hour)
			if n, err := a.DB.DeleteQueriesBefore(ctx, cutoff); err == nil && n > 0 {
				a.log.Info("query retention cleanup", "removed", n)
			}
		}
	}
}

func (a *App) healthLoop(ctx context.Context) {
	for {
		interval := time.Duration(a.GetSettings().HealthProbeIntervalSec) * time.Second
		if interval <= 0 {
			interval = 60 * time.Second
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(interval):
			domain := a.GetSettings().HealthProbeDomain
			if domain == "" {
				continue
			}
			a.Pool.Test(ctx, domain)
		}
	}
}
