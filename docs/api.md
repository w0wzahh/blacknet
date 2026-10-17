# API

The full OpenAPI 3.0 document is served live at `/api/v1/openapi.yaml`
(source: `internal/api/openapi.yaml`).

## Auth

- `POST /api/v1/auth/login` `{password}` → session cookie (`HttpOnly`,
  `SameSite=Strict`, 12 h). Per-IP rate limited.
- Bearer token for CLI/scripts: `<data_dir>/api.token` (0600),
  `Authorization: Bearer <token>`.
- Cookie-authenticated mutations must send `X-Requested-With: XMLHttpRequest`
  and, when present, a matching `Origin`.
- Before a password is set, GET endpoints are readable so the first-run wizard
  works; all mutations stay closed.

## Conventions

- JSON bodies; errors are `{"error": "..."}` optionally with `"fields"` for
  per-field validation failures.
- Pagination: `?page=&per_page=` (max 1000), responses carry `total`, `pages`.
- `GET /api/v1/queries/live` is SSE (`data:` = QueryEvent JSON, `:` heartbeats).
- Destructive/unsafe actions require explicit confirmation
  (`?confirm=true` on client stat reset, protection disable, restore).
