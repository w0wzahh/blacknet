# Policy groups and schedules

Blacknet filters per device by default, but most networks think in *roles*:
kids' tablets, IoT devices, work laptops. Policy groups let a set of clients
share rules, blocklists, upstreams and schedules.

## Groups

A group has a name, an optional description, an enabled flag, and an optional
upstream override. Disabling a group inactivates its scoped rules and
restricted blocklists without deleting anything.

A group can point at a different upstream resolver than the network default —
e.g. a filtered "family" upstream for the kids' group while everything else
uses your normal resolver.

## Assignments

A device joins a group through an assignment, evaluated in this order:

1. **Explicit client assignment** — bind a known client id (stable across IP
   changes once the device has been seen).
2. **Exact IP** — `192.168.1.50 → kids`.
3. **CIDR** — `192.168.2.0/24 → iot`; the most specific prefix wins when
   several overlap.

A client with no assignment gets global policies. On the Clients page you can
also set a client's group directly — that is equivalent to a client-kind
assignment.

Assignments reload live; there is no restart or lease renewal needed.

## Scoped rules and blocklists

- A rule created with a *group* scope applies to every member of that group.
  Precedence: client rules > group rules > global rules.
- A blocklist can be restricted to specific groups; unrestricted lists apply
  to everyone.
- Temporary rules (`expires_at`) work for every scope and are dropped
  automatically after expiry.

The Rules page has an inspector that shows the full decision trace for a
domain — which rule tier fired, which schedule or group applied, or why a
query fell through to the blocklists/default allow. The Policies page has the
same simulation against a chosen client, IP, or group.

## Schedules

Schedules change policy by time of day. Three effects exist:

- **protection_off** — filtering is skipped for the target while the window
  is active (e.g. unblock a game console in the evening).
- **protection_on** — the target is filtered while the window is active even
  if the global protection switch is off.
- **extra_lists** — additional blocklists (`list_ids`) apply to the target
  only while the window is active (e.g. social-media lists during homework
  hours).

Targets are a group or a single client. Weekdays, start/end times (windows
may cross midnight), an IANA timezone, and optional from/to dates are
configurable. `GET /api/v1/schedules/{id}/preview` shows the next activation
windows.

## Verifying assignments

`POST /api/v1/policies/simulate` with `{domain, client_ip}` returns the
resolved client, its group, and the decision trace — use it before assuming a
device is in a group.
