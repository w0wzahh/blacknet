<div align="center">

# Blacknet

**Self-hosted, network-wide DNS ad & tracker blocker with a real filtering engine and a dark admin dashboard.**

[![Version](https://img.shields.io/badge/version-2.0.0-8b5cf6)](https://github.com/w0wzahh/blacknet)
[![Go](https://img.shields.io/badge/Go-1.26-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20Docker%20%7C%20Pi-informational)](#platform-support)

*An original implementation inspired by the Pi-hole / AdGuard Home operational model — no account, no cloud, no telemetry.*

</div>

---

## Features

- **Real DNS resolver** — UDP + TCP on port 53 (or any port), answers every device on your LAN
- **Filtering engine** — blocks ad/tracker/malicious domains *before* a connection is attempted; blocked queries never leave your network
- **Upstream flexibility** — plain DNS (UDP/TCP), DNS-over-TLS and DNS-over-HTTPS with failover, health probes and latency analytics
- **TTL-correct caching** — min/max bounds and negative caching for faster resolution
- **Policy groups** — per-device or per-group filtering: scoped rules, blocklist restrictions, upstream overrides
- **Local DNS** — A/AAAA/CNAME/TXT/PTR records, wildcards and rewrites, resolved before filtering so internal names are never blocked
- **Rule intelligence** — decision traces (*"why was this blocked?"*), batch testing, conflict detection, temporary rules that expire automatically
- **Schedules** — recurring windows that pause protection, force it on, or enable extra blocklists per group/client
- **Discovery & inventory** — passive device detection, identity bindings, new-device alerts
- **Enforcement** — managed router integration (OpenWrt/SSH) with change preview, verified apply and one-click rollback; the dashboard reports configured vs. observed vs. enforced protection honestly
- **Operations** — optional built-in DHCP server, DNSSEC pass-through, audit log, health history, backup/restore, diagnostic bundle export
- **Dashboard** — live query log over SSE, per-client stats, analytics, and a setup wizard that walks through password, interfaces and router configuration

## Quick start

### Docker (recommended — requires Linux host networking for DHCP)

```sh
cp config.example.yaml config.docker.yaml   # adjust to your LAN
docker compose up -d --build
```

### From source

```sh
cd web && npm install && npm run build && cd ..   # dashboard
go build -o blacknet ./cmd/blacknet               # server
./blacknet init                                   # writes config.yaml
./blacknet serve                                  # port 53 needs admin/root
```

Open `http://<host>:8080` — the setup wizard walks you through the rest.

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
| Windows x64 | Service install via `deploy/windows/install.ps1` |
| Linux x64 | systemd unit via `deploy/linux/install.sh` |
| Linux ARM64 | `GOARCH=arm64` — runs fine on Raspberry Pi 4/5 |
| Docker | `docker compose up -d` (host networking for DHCP) |
| OpenWrt | Engine designed for it — see `deploy/openwrt/README.md` |

## Getting the network to use it

Blacknet filters only the devices that actually query it. Point your router's
DHCP-advertised DNS at the Blacknet host's LAN IP (reserve that IP first), or
use the built-in DHCP server on routers that can't advertise custom DNS.
Full walkthrough with IPv6 caveats and rollback:
**[docs/router-setup.md](docs/router-setup.md)**.

## Documentation

| Doc | Contents |
|---|---|
| [docs/installation.md](docs/installation.md) | Windows / Linux / Docker installs |
| [docs/router-setup.md](docs/router-setup.md) | DHCP/DNS router configuration + managed enforcement |
| [docs/policy-groups.md](docs/policy-groups.md) | Groups, assignments, scoped rules, schedules |
| [docs/dns-filtering.md](docs/dns-filtering.md) | Capabilities, local DNS, DNSSEC, honest limits |
| [docs/security.md](docs/security.md) | Auth, CSRF, SSRF policy, hardening checklist |
| [docs/troubleshooting.md](docs/troubleshooting.md) | Port conflicts, "nothing is blocked", etc. |
| [docs/architecture.md](docs/architecture.md) | Internals, precedence rules, failure modes |
| [docs/api.md](docs/api.md) | REST API reference (`GET /api/v1/openapi.yaml` live) |

## Developing

```sh
go build ./...        # backend
go test ./...         # unit + integration + e2e
cd web && npm run dev # Vite dev server on :5173, proxies /api to :18180
```

## Security & privacy

Runs entirely on your hardware: no account, no cloud backend, no telemetry.
The resolver refuses untrusted clients by CIDR allowlist, the dashboard
requires a password, and blocklists are fetched over HTTPS with SSRF
validation — never executed. Details: [docs/security.md](docs/security.md).

## Known limitations

DNS filtering blocks whole domains only — it cannot strip ads served from the
same domain as content, cannot see inside encrypted client DNS (DoH to
arbitrary endpoints), and cannot stop devices that bypass the configured
resolver. These are documented, visible limits of the design — not bugs.
See [docs/dns-filtering.md](docs/dns-filtering.md).

## Contributing

Issues and pull requests welcome. Blocklists belong to their respective
maintainers.

## License

MIT — see [LICENSE](LICENSE).
