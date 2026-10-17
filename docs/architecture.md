# Blacknet architecture

## Process layout

```
cmd/blacknet            CLI + service entrypoint (serve, status, test-dns, ...)
internal/
  app/                  composition root: builds and wires all components,
                        owns settings application and safe runtime reloads
  config/               YAML bootstrap config (listen addrs, data dir, CIDRs)
  dnsserver/            real DNS server: UDP+TCP listeners, trusted-client
                        enforcement, filter -> cache -> upstream pipeline
  filtering/            deterministic rule engine + blocklist parsers;
                        subjects carry client/group/schedule context
  policies/             policy groups, client/IP/CIDR assignment resolver,
                        per-group upstream overrides
  localdns/             local DNS records (A/AAAA/CNAME/TXT/PTR), wildcards,
                        reverse zones, conflict warnings
  schedules/            time-window policies (protection off/on per target)
  discovery/            passive device inventory (neighbor table, DHCP leases),
                        client identity bindings
  enforcement/          router integration adapters (OpenWrt/SSH), change
                        preview/apply/rollback with snapshots
  cache/                TTL-aware in-memory answer cache
  upstream/             UDP/TCP/DoT/DoH resolvers, failover, health probes
  blocklists/           downloads, ETag/hash caching, SSRF validation,
                        quality metrics, profiles, group restrictions
  database/             SQLite (modernc.org/sqlite), migrations, stores,
                        async batched query writer, statistics queries
  api/                  /api/v1 REST, SSE live stream, SPA hosting
  auth/                 argon2id passwords, sessions, API token, rate limit
  backup/               zip backup/restore with manifest validation
  network/              interface discovery + port checks
  events/               bounded fan-out bus for live query events
  settings/             persisted runtime settings model + validation
  logging/              slog setup
web/                    React + TypeScript + Vite + Tailwind SPA
tests/integration/      end-to-end test: real DNS + real API + real SQLite
deploy/                 systemd unit, Windows service scripts, OpenWrt notes
```

## Request path

```
client :53 ──► dnsserver.ServeDNS
                 │ trusted CIDR check ──► REFUSED + log
                 │ SubjectFor(ip) ──► {clientID, groupID} via policies.Resolver
                 │ localdns.Store ──► local record hit: answer directly
                 │ filtering.Engine.Decide(domain, subject)
                 │   blocked ──► synthesize NXDOMAIN / null answer
                 │   allowed ──► cache.Get ──► hit: serve stale-free copy
                 │             └─► miss: upstream.Pool.Exchange
                 │                     (group upstream override if set;
                 │                      Do bit added when DNSSEC mode on)
                 │                     ├─ ok  → cache.Store, reply
                 │                     └─ err → SERVFAIL, log upstream failure
                 └──► nonblocking publish → (SQLite writer queue, SSE hub)
```

The DNS hot path never touches SQLite synchronously: events go to a bounded
channel drained by a batch writer (512 rows or 500 ms). If the channel fills,
events are dropped and counted (`log_events_dropped` in /status) rather than
growing memory or stalling resolution.

## Rule precedence (deterministic)

1. Local DNS records (authoritative answers, including wildcards and PTR)
2. Protection switch and `protection_off` schedules
3. Exact-domain rules — client-scoped > group-scoped > global
4. Tree rules — most specific suffix wins; ties: client > group > global,
   block > allow
5. Blocklist `@@` exception domains (tree match), honouring group restrictions
6. Blocklist block domains (tree match), honouring group restrictions
7. Default allow → upstream resolution (per-group upstream override if set)

`Engine.Decide` and `Engine.Explain` share one evaluation path — the API
simulator returns the same decision plus a human-readable trace. Disabled
groups contribute no rules or list restrictions; expired rules are dropped at
snapshot build.

Engine state is rebuilt atomically on any change (`Engine.Replace`), so rule
and blocklist edits apply without restarting listeners.

## Persistence

SQLite, WAL mode, single connection (serialized writes), busy_timeout 5s.
Tables: settings, clients, queries, blocklists, blocklist_domains,
blocklist_history, list_groups, rules, upstreams, health_history, audit,
policy_groups, policy_assignments, client_identities, discovery_events,
local_dns, schedules, enforcement_ops, schema_migrations. Retention worker
deletes old query rows every 6 h per `query_retention_days`; audit and
discovery events are bounded separately.

## Security surface

- DNS refuses non-trusted source IPs (configured CIDR allowlist; never an open
  resolver).
- API/dashboard need a session (argon2id password) or the local bearer token
  (`<data_dir>/api.token`, mode 0600).
- Cookie-authenticated mutations require `X-Requested-With` (CSRF) and a
  matching Origin when present.
- Login is rate-limited per IP; secrets never appear in API responses or logs.
- Blocklist fetches: https-only by default, private/loopback targets rejected,
  redirect targets re-validated, resolved IPs re-checked at dial time,
  64 MiB cap, timeouts, downloaded data is parsed as text and never executed.
- No telemetry; the optional update check is off by default.
