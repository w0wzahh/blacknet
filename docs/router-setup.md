# Router DNS setup

Blacknet is the resolver; your router's job is only to *tell clients to use
it*. Most routers advertise a DNS server address via DHCP — point it at the
Blacknet host.

## Generic steps (most routers)

1. Give the Blacknet host a fixed IP:
   - Preferred: a **DHCP reservation** in the router (binds the host's MAC to
     its current IP).
   - Alternative: configure the host with a static IP outside the DHCP pool.
2. In the router admin UI find **LAN / DHCP Server → DNS server** (sometimes
   under "Local Network", "DHCP", or "Internet → DNS"). Set primary DNS to the
   Blacknet host IP. Leave secondary empty — a public fallback DNS lets
   clients bypass filtering.
3. Save/apply. Renew DHCP leases on clients (reboot, or reconnect to Wi-Fi).

## Verifying clients picked it up

- Windows client: `ipconfig /all` → "DNS Servers" should list the Blacknet IP.
- Then `nslookup doubleclick.net` should return NXDOMAIN once blocklists load.
- The Blacknet dashboard → Clients should show the device; Query Log shows
  its queries live.

## Rolling back

Set the router's DNS fields back to "automatic" (or the previous values) and
renew client leases. Nothing else needs undoing — Blacknet never touched the
router itself.

## Common vendor notes

These are typical menu locations; firmware versions differ:

- **ISP all-in-one boxes**: often lock LAN DNS. If so: put the box in
  bridge mode behind your own router, or use Blacknet's optional DHCP server
  (Settings) after disabling the box's DHCP.
- **TP-Link**: Advanced → Network → LAN Settings → DNS.
- **Netgear**: Advanced → Setup → LAN Setup → DNS Address; or Internet → DNS.
- **Asus**: LAN → DHCP Server → DNS and WINS Server.
- **Ubiquiti (UniFi)**: Network → edit network → DHCP → DNS Server.
- **OpenWrt**: Network → Interfaces → LAN → DHCP Server → Advanced →
  DHCP-Options `6,<blacknet-ip>`.

## IPv6

If your LAN hands out IPv6, clients may also receive an IPv6 DNS server.
Either advertise Blacknet's IPv6 address too, or disable IPv6 DNS
advertisement in the router. Otherwise some queries will bypass filtering.

## Hard enforcement (advanced, optional)

DNS-based filtering can be bypassed by devices that ignore the advertised
resolver. On routers you administer, a firewall rule that redirects or blocks
outbound UDP/TCP 53 (and 853 for DoT) to servers *other than* Blacknet closes
the common bypass. This cannot defeat DoH to arbitrary HTTPS endpoints — that
requires blocking known DoH providers or deeper policy, with real trade-offs.
See docs/dns-filtering.md for honest limits.

### Managed enforcement

The Enforcement page can drive supported routers directly. Today the adapter
is **OpenWrt over SSH**: it configures dnsmasq's `dhcp_option` DNS
advertisement, adds redirect rules for outbound DNS/DoT, and reloads the
services. Every change is previewed first (the exact commands and affected
settings), snapshotted before apply, and reversible with one-click rollback.

Enforcement only marks protection as *enforced* when an apply operation has
verified the change on the router. The dashboard honestly distinguishes three
states:

- **configured** — a router integration exists but nothing was applied, or
  the router wasn't reachable,
- **observed** — clients are actually querying Blacknet (traffic evidence),
- **enforced** — a verified apply operation is in effect.

Devices on routers without an adapter still need the manual firewall rules
above; the dashboard will say "configured" rather than claiming protection it
cannot verify.
