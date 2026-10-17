# Installation

## Prerequisites

- A machine that stays on and has a wired or stable connection to the router:
  Windows 10/11 x64, any modern Linux x64/ARM64 (Raspberry Pi 4/5 works),
  or Docker.
- Port 53 (UDP+TCP) free on the host, and permission to open it.
- Access to your router's settings to change the advertised DNS server.

## Quick start (development / evaluation)

```sh
# backend
go build -o blacknet ./cmd/blacknet

# frontend
cd web && npm install && npm run build && cd ..

# config
./blacknet init            # writes config.yaml
$EDITOR config.yaml        # review listen addresses

./blacknet serve           # may need admin/root for port 53
```

Dashboard: `http://<host>:8080` — first visit runs the setup wizard
(password, network detection, validation, router instructions).

## Windows (service)

1. Build or download `blacknet.exe`, `config.yaml`, and `web/dist`.
2. Elevated PowerShell:

   ```powershell
   cd deploy\windows
   .\install.ps1 -SourceDir <folder-with-blacknet.exe>
   ```

   The script copies files to `%ProgramData%\Blacknet`, adds inbound firewall
   rules for port 53 (Private profile) and the dashboard, registers an
   auto-start service with restart-on-failure, and starts it.
3. `.\uninstall.ps1` removes it (`-Purge` also deletes data).

Notes:
- Port 53 conflicts: `netstat -an | findstr ":53 "` and check for
  Internet Connection Sharing or other DNS software.
- This PC's own DNS does not need to point at Blacknet — leave it on the
  router/upstream so the machine still resolves if the service stops.

## Linux (systemd)

```sh
make build && make web
cd deploy/linux && sudo sh install.sh
```

Installs to `/usr/local/bin/blacknet`, config at `/etc/blacknet/config.yaml`,
data at `/var/lib/blacknet`, systemd unit with `CAP_NET_BIND_SERVICE` so the
service runs unprivileged.

## Docker Compose

```sh
cp config.example.yaml config.docker.yaml   # edit if needed
docker compose up -d --build
docker compose logs -f
```

Ports `53/udp`, `53/tcp`, `8080/tcp`; state in the `blacknet-data` volume.

## Verifying it works

```sh
blacknet test-dns example.com --server <host-ip>:53   # should resolve
blacknet test-dns doubleclick.net --server <host-ip>:53  # should NXDOMAIN once lists load
```

Then point a device (or the router) at the host and watch the dashboard's
Query Log.
