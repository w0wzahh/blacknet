# What DNS filtering does — and doesn't do

## How it works

When a device asks for `ads.example.com`, Blacknet checks its rules before
forwarding anything upstream:

- **Blocked** → returns NXDOMAIN (default) or a null answer (0.0.0.0/::) —
  the connection is never made, and the request never reaches your upstream
  resolver.
- **Allowed** → resolved normally via your configured upstreams, cached per
  TTL, and logged (metadata only).

## What it can block

- Ad/tracker domains on imported lists or your custom rules.
- Malware/phishing domains included in security lists.
- Whole domain trees (`*.example.com`) — cheap and effective.

## Honest limits

- **Same-domain ads**: ads served from the same domain as content (YouTube,
  Instagram, Facebook in-feed, Spotify) are indistinguishable at DNS level.
  No DNS blocker can remove them; use browser content blockers in addition.
- **Client bypass**: devices/apps with their own DNS (DoH in browsers, VPNs,
  hard-coded resolvers, some smart TVs) can skip Blacknet entirely. DNS logs
  cannot prove a device *isn't* bypassing.
- **Encrypted DNS**: DoH/DoT inside apps is invisible to any DNS-layer filter.
  Blocking it reliably means controlling port 53/853 egress and known DoH
  endpoints at the router — advanced, optional, and imperfect.
- **First-party tracking**: DNS blocking hides nothing from a domain you still
  contact for content.

## Bypass checklist (diagnostics)

A device "not being filtered" usually means one of:

1. It never switched DNS — check its active resolver (`ipconfig /all`,
   `resolvectl status`, connection details on mobile).
2. The router still advertises itself/ISP DNS — renew the DHCP lease.
3. IPv6 clients got an IPv6 DNS server — advertise Blacknet over IPv6 or
   disable IPv6 DNS on the router.
4. The app/browser uses its own DoH — check the app's "secure DNS" setting.
5. A VPN is routing DNS through the tunnel.

The dashboard's Network Setup page runs a live diagnostic that checks the
service, the rule engine, upstream health, and whether your current device is
a recognized client.

## Local DNS records

The Local DNS page serves authoritative answers from Blacknet itself — A/AAAA
forward records, PTR reverse records, CNAMEs, TXT, and `*.name` wildcards.
Local records resolve *before* filtering rules, so an internal name can never
be blocked by accident. Conflicting records (e.g. a CNAME beside other types
on the same name) are flagged with warnings rather than silently broken.
`POST /api/v1/local-dns/test` resolves a name against the table without
sending a live query.

## DNSSEC mode

Settings → DNSSEC mode asks upstreams to validate by setting the DO bit on
forwarded queries and records the result per query: `authenticated` when the
upstream returned the AD bit, `unsigned` otherwise. Blacknet reports the
outcome in the query log but does not itself validate signatures — validation
is delegated to your upstream resolver.

## Per-device filtering

Policy groups, per-client rules, group-scoped blocklists and schedules are
covered in docs/policy-groups.md.
