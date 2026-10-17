# Blacknet

Self-hosted, network-wide DNS ad and tracker blocker — a real DNS server with
a filtering engine, blocklist manager, caching resolver, REST API and a dark
web dashboard. Original implementation inspired by the Pi-hole / AdGuard Home
operational model.

## What it does

- Answers DNS (UDP + TCP, port 53 or any configured port) for your LAN.
- Blocks ad/tracker/malicious domains *before* a connection is attempted —
  blocked queries are never sent upstream.
- Forwards allowed queries to configurable upstreams: plain DNS (UDP/TCP),
  DNS-over-TLS and DNS-over-HTTPS, with failover and health probes.
- TTL-correct response caching with min/max bounds and negative caching.
- Live query log (SSE), per-client statistics, custom allow/block rules with
  deterministic precedence, blocklist imports with ETag/hash refresh,
  backups, and an honest explanation of what DNS filtering can't do.
- **Policy groups**: assign devices by client, IP or CIDR; per-group rules,
  blocklist restrictions, upstream overrides and schedules.
- **Local DNS**: A/AAAA/CNAME/TXT/PTR records, wildcards and PTR zones,
  resolved before filtering so internal names are never blocked.
- **Rule intelligence**: decision traces ("why was this blocked?"), batch
  testing, conflict detection, temporary rules that expire automatically.
- **Schedules**: recurring windows that suspend filtering, force it on, or
  enable extra blocklists for a group or client.
- **Discovery & inventory**: passive device detection (neighbor table, DHCP
  leases), identity bindings, new-device events.
- **Enforcement**: managed router integration (OpenWrt/SSH) with change
  preview, verified apply, and one-click rollback — the dashboard reports
  configured vs observed vs enforced protection honestly.
- **Operations**: DNSSEC delegation to upstreams, latency/error analytics,
  health history, audit log, diagnostic bundle export.

## Quick start

```sh
# 1. build the dashboard
cd web && npm install && npm run build && cd ..

# 2. build the server
go build -o blacknet ./cmd/blacknet

# 3. example config, then run
./blacknet init          # writes config.yaml
./blacknet serve         # port 53 needs admin/root; edit config.yaml first if taken
```

Open `http://<host>:8080` — the setup wizard walks through password,
interfaces, validation and router configuration.

### Smoke test without a browser

```sh
./blacknet test-dns example.com        # resolves via upstream
./blacknet test-dns doubleclick.net    # NXDOMAIN once lists refresh
./blacknet status                      # live counters as JSON
./blacknet test-rule ads.example.com   # engine decision, no server needed
```

## Platform support

| Platform | Status |
|---|---|
| Windows x64 | supported (service via `deploy/windows/install.ps1`) |
| Linux x64 | supported (systemd unit via `deploy/linux/install.sh`) |
| Linux ARM64 | supported (`GOARCH=arm64`; Pi 4/5 fine) |
| Docker | `docker compose up -d --build` |
| OpenWrt | engine designed for it; package not shipped in V1 — see `deploy/openwrt/README.md` |

## Getting the network to use it

Blacknet filters only devices that actually query it. In your router, set the
DHCP-advertised DNS to this host's LAN IP (reserve it first). Full
walkthrough including IPv6 caveats and rollback: **docs/router-setup.md**.

## Documentation

- `docs/installation.md` — Windows/Linux/Docker installs
- `docs/router-setup.md` — DHCP/DNS router configuration + managed enforcement
- `docs/policy-groups.md` — groups, assignments, scoped rules, schedules
- `docs/dns-filtering.md` — capabilities, local DNS, DNSSEC, and honest limits
- `docs/security.md` — auth, CSRF, SSRF policy, hardening checklist
- `docs/troubleshooting.md` — port conflicts, "nothing is blocked", etc.
- `docs/architecture.md` — internals, precedence rules, failure modes
- `GET /api/v1/openapi.yaml` — OpenAPI spec (served by the running app)

## Developing

```sh
go build ./...          # backend
go test ./...           # unit + integration + e2e
go test -bench=. -benchmem ./internal/dnsserver/   # benchmark
# race detector needs CGO: CGO_ENABLED=1 go test -race ./...   (Linux/macOS/CI)

cd web && npm run dev   # Vite dev server on :5173, proxies /api to :18180
```

## Security & privacy

Runs entirely on your hardware: no account, cloud backend, telemetry or
update check (unless you enable one). The resolver refuses untrusted clients
by CIDR allowlist; the dashboard requires a password; blocklists are fetched
over HTTPS with SSRF validation and never executed. Details: `docs/security.md`.

## Known limitations

DNS filtering blocks whole domains only — it cannot strip ads served from the
same domain as content, cannot see inside encrypted client DNS, and cannot
stop devices that bypass the configured resolver. These are documented,
visible limits of the design, not bugs. See `docs/dns-filtering.md`.

## License

MIT — see LICENSE. Blocklists belong to their respective maintainers.
