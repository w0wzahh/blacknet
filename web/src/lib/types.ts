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
  comment: string
  enabled: boolean
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
