# Blacknet on OpenWrt (future integration)

V1 does not ship an OpenWrt package. The codebase is structured so the same
filtering engine (`internal/filtering`), DNS server (`internal/dnsserver`),
upstream pool and cache can run on a router in a later package.

Requirements for a future port:

- OpenWrt 23.05+ on a device with >= 128 MB free RAM and ~40 MB free storage
  (blocklists and the SQLite database live on flash; consider extroot or
  `data_dir` on USB for large lists).
- Go 1.26 cross-compile: `GOOS=linux GOARCH=<router arch> CGO_ENABLED=0`
  (`mips`, `mipsle`, `arm`, `aarch64` all build today).
- The stock `dnsmasq`/`odhcpd` on OpenWrt already handles DHCP — Blacknet
  should replace only the DNS-forwarding role: point dnsmasq's upstream to
  Blacknet (`127.0.0.1#5353`-style) instead of running Blacknet's optional
  DHCP mode.
- Port 53 conflicts with dnsmasq: either move dnsmasq off port 53 and let it
  forward to Blacknet, or keep dnsmasq on 53 and forward `server=` entries to
  Blacknet on an alternate port. The former gives per-query filtering.

Do NOT run Blacknet's DHCP server on a router that already runs dnsmasq —
two DHCP servers on one LAN cause client conflicts.
