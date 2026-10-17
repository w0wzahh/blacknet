# Security model

## Goals and defaults

- **Never an open resolver.** DNS answers only for client IPs inside
  `trusted_cidrs` (default: RFC1918 + loopback + link-local + ULA). Others
  get REFUSED.
- **Authenticated administration.** Dashboard/API need a session or the local
  API token. Passwords are hashed with argon2id (64 MiB memory, t=3, p=2).
- **CSRF protection.** Cookie-authenticated mutations require the
  `X-Requested-With` header and a matching `Origin` when present. The session
  cookie is `HttpOnly` + `SameSite=Strict`.
- **Rate limiting.** Login attempts are limited per source IP.
- **SSRF defense for blocklists.** HTTPS only by default; private/loopback/
  link-local/multicast targets rejected, including after redirects and at
  dial time. Local sources are possible via the explicit
  `allow_private_lists` setting.
- **Untrusted input.** Blocklists are parsed as text into domain sets —
  never executed, never eval'd. Size (64 MiB), timeout and redirect limits
  apply. A refresh that yields zero valid domains keeps the previous list.
- **No secrets in responses/logs.** The password hash and API token are never
  returned by the API; the token file is mode 0600.
- **No telemetry.** Nothing is sent anywhere except your configured upstream
  DNS queries and the blocklist downloads you configured. The update check is
  off by default.
- **Safe mutations.** Settings are validated before persisting; last-valid
  config survives a rejected change. Blocking changes apply at runtime;
  listener changes require a restart and are only in config.yaml.
- **Audit trail.** Sensitive actions (login, rule/list/upstream/settings
  changes, backup/restore, cache flush, protection toggle) are recorded in
  the `audit` table — see GET /api/v1/audit.

## Failure behavior

- Upstream down → try the next configured upstream; all down → SERVFAIL +
  health warning in the dashboard. Never silently falls back to an
  unfiltered resolver.
- Database errors → logged, DNS keeps serving; the query log reports
  `dropped_events` so gaps are visible rather than silent.
- Crash → the service manager (systemd/Windows service/Docker) restarts it;
  configuration lives in SQLite and the YAML file.

## Hardening checklist for production

1. Keep `web.listen` on the LAN or localhost — do not port-forward 8080.
2. Do not port-forward port 53 from the internet. Ever.
3. Set a strong admin password during setup.
4. Keep `trusted_cidrs` limited to your actual LAN ranges.
5. Keep Go dependencies updated (`go get -u ./... && go mod tidy`, then test).
6. Back up via the dashboard or `blacknet backup`.
