export interface Status {
  version: string
  protection_enabled: boolean
  blocking_mode: string
  dns_listeners: string[]
  trusted_cidrs: string[]
  queries_total: number
  queries_blocked: number
  queries_refused: number
  upstream_failures: number
  log_events_dropped: number
  cache: { entries: number; hits: number; misses: number; evictions: number; inserts: number; max_size: number }
  cache_hit_rate: number
  upstreams_healthy: number
  upstreams_total: number
  active_blocklists: number
  blocklist_domains: number
  custom_rules: number
  known_clients: number
  settings: Settings
}

export interface Settings {
  protection_enabled: boolean
  blocking_mode: 'nxdomain' | 'null'
  cache_enabled: boolean
  cache_max_entries: number
  cache_min_ttl_seconds: number
  cache_max_ttl_seconds: number
  blocklist_refresh_hours: number
  query_retention_days: number
  parallel_upstreams: boolean
  allow_private_lists: boolean
  health_probe_domain: string
  health_probe_interval_seconds: number
  setup_completed: boolean
  query_logging_enabled: boolean
  discovery_enabled: boolean
  discovery_interval_seconds: number
  dnssec_upstream: boolean
  audit_retention_days: number
}

export interface QueryRow {
  id: number
  time: string
  client_ip: string
  client_id: number
  alias?: string
  domain: string
  qtype: number
  qtype_name?: string
  blocked: boolean
  reason: string
  rcode: number
  rcode_name?: string
  latency_ms: number
  cached: boolean
}

export interface Client {
  id: number
  ip: string
  alias: string
  group: string
  policy_group_id: number
  policy_group?: string
  classification: string
  identity_source: string
  notes: string
  first_seen: string
  last_seen: string
  total_queries: number
  blocked_queries: number
  block_pct: number
}

export interface Blocklist {
  id: number
  name: string
  url: string
  enabled: boolean
  last_refresh?: string
  last_error?: string
  rule_count: number
  content_hash?: string
  created_at: string
}

export interface Rule {
  id: number
  domain: string
  action: 'allow' | 'block'
  scope: 'exact' | 'tree'
  client_id: number
  group_id: number
  comment: string
  enabled: boolean
  expires_at?: string
  list_id?: number
}

// ---------- V2 ----------

export interface PolicyGroup {
  id: number
  name: string
  description: string
  enabled: boolean
  upstream_id: number
  created_at: string
  updated_at: string
  client_count?: number
  list_ids?: number[]
}

export interface Assignment {
  id: number
  kind: 'client' | 'ip' | 'cidr' | string
  value: string
  group_id: number
  group_name?: string
  created_at: string
}

export interface Subject {
  client_id: number
  group_id: number
  now: string
}

export interface Step {
  stage: string
  matched: boolean
  detail: string
  rule?: Rule
  list_id?: number
}

export interface Explanation {
  decision: Decision
  subject: Subject
  active_schedules?: string[]
  protection_off: boolean
  steps: Step[]
}

export interface RuleConflict {
  rule_id: number
  domain: string
  relation: 'conflict' | 'shadowed' | 'redundant' | 'covers' | string
  detail: string
}

export interface InspectResult {
  domain: string
  subject: Subject
  explanation: Explanation
  matched_rules: Rule[]
  in_blocklists: { list_id: number; name: string; matched_domain: string }[]
  exceptions: { list_id: number; name: string; matched_domain: string }[]
}

export interface BatchResult {
  subject: Subject
  results: { domain: string; blocked: boolean; reason: string; trace: Step[] }[]
}

export interface Schedule {
  id: number
  name: string
  description: string
  enabled: boolean
  tz: string
  days_mask: number
  start_min: number
  end_min: number
  date_from: string
  date_to: string
  target_kind: 'protection' | 'group' | string
  target_id: number
  effect: 'allow_all' | 'block_all' | 'extra_lists' | string
  list_ids?: number[]
  created_at: string
  updated_at: string
}

export interface SchedulePreview {
  schedule: Schedule
  at: string
  active: boolean
  transitions: { at: string; to_active: boolean }[]
}

export interface LocalRecord {
  id: number
  name: string
  type: 'A' | 'AAAA' | 'CNAME' | 'TXT' | 'PTR' | string
  value: string
  ttl: number
  enabled: boolean
  comment: string
  created_at: string
  updated_at: string
}

export interface DiscoveryEvent {
  id: number
  kind: string
  value: string
  detail: string
  first_seen: string
  last_seen: string
  count: number
  notified: boolean
}

export interface Identity {
  id: number
  client_id: number
  kind: string
  value: string
  created_at: string
}

export interface ListHistoryEntry {
  id: number
  ts: string
  status: 'ok' | 'unchanged' | 'failed' | string
  rule_count: number
  bytes: number
  malformed: number
  duplicates: number
  hash: string
  error?: string
}

export interface UpstreamHealthEntry {
  ts: string
  ok: boolean
  rtt_ms: number
  error?: string
}

export interface AuditEntry {
  id: number
  ts: string
  actor: string
  action: string
  resource: string
  detail: string
  result: string
}

export interface EnforcementOp {
  id: number
  ts: string
  integration: string
  action: string
  status: string
  preview: string
  result: string
  actor: string
}

export interface Integration {
  id: string
  name: string
  available: boolean
  reason?: string
  verified: boolean
  last_error?: string
  notes?: string
}

export interface EnforcementPlan {
  integration: string
  action: string
  summary: string
  commands: string[]
  warnings: string[]
  requires_confirm?: string[]
}

export interface Upstream {
  id: number
  name: string
  protocol: 'udp' | 'tcp' | 'dot' | 'doh'
  address: string
  priority: number
  timeout: number
  enabled: boolean
  stats: {
    last_rtt_ms: number
    last_error?: string
    last_check?: string
    healthy: boolean
    queries: number
    failures: number
  }
}

export interface Decision {
  blocked: boolean
  reason: string
  rule?: Rule
  list_id?: number
}

export interface Summary {
  total_queries: number
  blocked_queries: number
  allowed_queries: number
  block_pct: number
  unique_domains: number
  active_clients: number
  cached_queries: number
  avg_latency_ms: number
}

export interface Bucket {
  ts: string
  total: number
  blocked: number
  allowed: number
}

export interface TopItem {
  value: string
  total: number
  blocked: number
  alias?: string
}

export interface NetInterface {
  name: string
  addrs: string[]
  ipv4: string[]
  is_up: boolean
  is_loopback: boolean
}

export interface NetworkInfo {
  primary_ipv4: string
  gateway_guess: string
  dns_listen: string[]
  web_listen: string
  trusted_cidrs: string[]
  port_available: Record<string, boolean>
}

export interface Diagnostics {
  dns_service: string
  db_ok: boolean
  test_domain: string
  test_decision: Decision
  protection_enabled: boolean
  upstreams_healthy: number
  upstreams_total: number
  caller_ip: string
  caller_known: boolean
}
