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
  filtering/            deterministic rule engine + blocklist parsers
  cache/                TTL-aware in-memory answer cache
  upstream/             UDP/TCP/DoT/DoH resolvers, failover, health probes
  blocklists/           downloads, ETag/hash caching, SSRF validation
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
                 │ filtering.Engine.Decide(domain, clientID)
                 │   blocked ──► synthesize NXDOMAIN / null answer
                 │   allowed ──► cache.Get ──► hit: serve stale-free copy
                 │             └─► miss: upstream.Pool.Exchange
                 │                     ├─ ok  → cache.Store, reply
                 │                     └─ err → SERVFAIL, log upstream failure
                 └──► nonblocking publish → (SQLite writer queue, SSE hub)
```

The DNS hot path never touches SQLite synchronously: events go to a bounded
channel drained by a batch writer (512 rows or 500 ms). If the channel fills,
events are dropped and counted (`log_events_dropped` in /status) rather than
growing memory or stalling resolution.

## Rule precedence (deterministic)

1. Exact-domain **allow** rules (client-scoped beats global)
2. Exact-domain **block** rules (client-scoped beats global)
3. Tree rules — the most specific match wins; ties: client-scoped > global,
   block > allow
4. Blocklist `@@` exception domains (tree match)
5. Blocklist block domains (tree match)
6. Default allow → upstream resolution

Engine state is rebuilt atomically on any change (`Engine.Replace`), so rule
and blocklist edits apply without restarting listeners.

## Persistence

SQLite, WAL mode, single connection (serialized writes), busy_timeout 5s.
Tables: settings, clients, queries, blocklists, blocklist_domains, rules,
upstreams, audit, schema_migrations. Retention worker deletes old query rows
every 6 h per `query_retention_days`.

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
