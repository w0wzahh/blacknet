# Troubleshooting

## Server won't start: "bind udp ...:53 ... permission denied"

Port 53 is privileged. Windows: run as Administrator or use the service
(deploy/windows/install.ps1). Linux: use the systemd unit (has
CAP_NET_BIND_SERVICE) or run with sudo.

## Server won't start: "address already in use"

Something else holds port 53:

- Windows: `netstat -ano | findstr ":53"` → find the PID (`tasklist | findstr <pid>`).
  Common culprits: Internet Connection Sharing, Hyper-V NAT, other DNS software.
- Linux: `ss -lunpt | grep :53` — usually systemd-resolved
  (`sudo systemctl disable --now systemd-resolved` or set DNSStubListener=no),
  dnsmasq, or another AdGuard/Pi-hole install.

Or change `dns.listen` in config.yaml to another port for testing.

## Devices still see ads / aren't filtered

See docs/dns-filtering.md "Bypass checklist". Fastest check: on the device,
`nslookup <domain>` should list the Blacknet IP as the server. If not, the
device isn't using Blacknet at all — fix DHCP/router first.

## Dashboard shows upstreams failing

- `blacknet test-dns example.com` → isolates server vs client issues.
- Settings → Upstream DNS → "Test all" does real resolutions and shows
  per-resolver errors and latency.
- Check the machine's own connectivity: it must reach the upstream itself.
- A VPN or firewall on the host can block outbound 53/853/443.

## Everything resolves (nothing blocked)

- Dashboard → Overview → "Protection on"? (a big off state is shown)
- Custom Rules → "Test domain" runs the real engine — e.g. `doubleclick.net`
  should be blocked once lists refresh.
- Blocklists page: check each list's Last refresh / Error columns; a failed
  first download yields 0 rules.

## Query log empty but queries work

- `log_events_dropped` in /api/v1/status > 0 means the DB writer can't keep
  up — check disk and CPU.
- The log is batched (up to ~0.5 s delay). Hard refresh the page.

## Restore previous router settings

Router DNS fields back to automatic/previous values, then renew client
leases (reconnect Wi-Fi or reboot). Blacknet never modified the router.
