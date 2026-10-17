import { useEffect, useState } from 'react'
import {
  AreaChart, Area, PieChart, Pie, Cell,
  XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid, Legend,
} from 'recharts'
import { api, fmtNum, fmtTime, fmtTimeShort } from '../lib/api'
import { Bucket, TopItem, Summary, Status } from '../lib/types'
import { Badge, EmptyState, ErrorBox, Loading, Modal, Field, PageHeader, SectionLabel, StatCard, RankList, chartTooltip, chartLegend } from '../components/ui'
import { SearchCode } from 'lucide-react'

const WINDOWS = [
  { v: '1h', label: '1 hour' },
  { v: '24h', label: '24 hours' },
  { v: '7d', label: '7 days' },
  { v: '30d', label: '30 days' },
]

export function Analytics() {
  const [win, setWin] = useState('24h')
  const [series, setSeries] = useState<Bucket[]>([])
  const [summary, setSummary] = useState<Summary | null>(null)
  const [status, setStatus] = useState<Status | null>(null)
  const [topBlocked, setTopBlocked] = useState<TopItem[]>([])
  const [topQueried, setTopQueried] = useState<TopItem[]>([])
  const [topClients, setTopClients] = useState<TopItem[]>([])
  const [latency, setLatency] = useState<LatencyStats | null>(null)
  const [errors, setErrors] = useState<RCodeStat[]>([])
  const [groupStats, setGroupStats] = useState<GroupStat[]>([])
  const [investigate, setInvestigate] = useState(false)
  const [err, setErr] = useState<unknown>(null)

  const load = async () => {
    try {
      const buckets = win === '1h' ? 60 : win === '24h' ? 48 : win === '7d' ? 84 : 120
      const [ts, sum, st, tb, tq, tc, lat, errs, gs] = await Promise.all([
        api.get<Bucket[]>(`/api/v1/stats/timeseries?window=${win}&buckets=${buckets}`),
        api.get<Summary>(`/api/v1/stats/summary?window=${win}`),
        api.get<Status>('/api/v1/status'),
        api.get<TopItem[]>(`/api/v1/stats/top-domains?blocked=true&limit=10&window=${win}`),
        api.get<TopItem[]>(`/api/v1/stats/top-domains?limit=10&window=${win}`),
        api.get<TopItem[]>(`/api/v1/stats/top-clients?limit=10&window=${win}`),
        api.get<LatencyStats>(`/api/v1/stats/latency?window=${win}`),
        api.get<RCodeStat[]>(`/api/v1/stats/errors?window=${win}`),
        api.get<GroupStat[]>(`/api/v1/stats/groups?window=${win}`),
      ])
      setSeries(ts ?? []); setSummary(sum); setStatus(st)
      setTopBlocked(tb ?? []); setTopQueried(tq ?? []); setTopClients(tc ?? [])
      setLatency(lat); setErrors(errs ?? []); setGroupStats(gs ?? [])
      setErr(null)
    } catch (e) { setErr(e) }
  }
  useEffect(() => { load() }, [win])

  if (!summary || !status) return <Loading />
  // Cached replies only happen for allowed queries, so the three slices must
  // be disjoint: forwarded = allowed - cached.
  const cached = Math.min(summary.cached_queries, summary.allowed_queries)
  const forwarded = summary.allowed_queries - cached
  const slices = [
    { name: 'Forwarded', value: forwarded, color: '#34d399' },
    { name: 'Cached', value: cached, color: '#60a5fa' },
    { name: 'Blocked', value: summary.blocked_queries, color: '#8b5cf6' },
  ]

  return (
    <div className="space-y-5">
      <PageHeader title="Analytics" desc="Traffic, decisions and latency for the selected window.">
        <button className="btn-ghost" onClick={() => setInvestigate(true)}>
          <SearchCode className="h-3.5 w-3.5" /> Investigate domain
        </button>
        <div className="seg">
          {WINDOWS.map(w => (
            <button key={w.v} onClick={() => setWin(w.v)}
              className={`seg-item ${win === w.v ? 'seg-item-active' : ''}`}>
              {w.label}
            </button>
          ))}
        </div>
      </PageHeader>
      <ErrorBox error={err} />

      {summary.total_queries === 0 ? (
        <EmptyState title="No data in this window" hint="Analytics are computed from real logged queries. Generate some DNS traffic first." />
      ) : (
        <>
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 xl:grid-cols-6">
            <StatCard label="Total queries" value={fmtNum(summary.total_queries)} sub={`last ${WINDOWS.find(w => w.v === win)?.label}`} />
            <StatCard label="Blocked" value={fmtNum(summary.blocked_queries)} accent sub={`${summary.block_pct.toFixed(1)}% of traffic`} />
            <StatCard label="Cached" value={fmtNum(cached)} sub={`${status.cache_hit_rate.toFixed(1)}% hit rate`} />
            <StatCard label="Unique domains" value={fmtNum(summary.unique_domains)} />
            <StatCard label="Active clients" value={fmtNum(summary.active_clients)} />
            <StatCard label="Avg latency" value={`${summary.avg_latency_ms.toFixed(1)}ms`} />
          </div>

          <div className="grid gap-4 lg:grid-cols-3">
            <div className="card p-4 lg:col-span-2">
              <SectionLabel>Queries over time</SectionLabel>
              <div className="h-56">
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={series} margin={{ top: 8, right: 8, bottom: 0, left: 0 }}>
                    <CartesianGrid stroke="#27272a" vertical={false} />
                    <XAxis dataKey="ts" tickFormatter={t => fmtTimeShort(t)} tick={{ fontSize: 10, fill: '#71717a' }} tickLine={false} axisLine={false} minTickGap={40} />
                    <YAxis width={30} tick={{ fontSize: 10, fill: '#71717a' }} tickLine={false} axisLine={false} allowDecimals={false} />
                    <Tooltip {...chartTooltip} labelFormatter={l => fmtTime(l as string)} />
                    <Legend wrapperStyle={chartLegend} />
                    <Area type="monotone" dataKey="allowed" stackId="1" stroke="#34d399" fill="#34d399" fillOpacity={0.25} name="Allowed" />
                    <Area type="monotone" dataKey="blocked" stackId="1" stroke="#8b5cf6" fill="#8b5cf6" fillOpacity={0.35} name="Blocked" />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            </div>
            <div className="card p-4">
              <SectionLabel>Decision share</SectionLabel>
              <div className="flex h-56 items-center gap-4">
                <div className="relative h-36 w-36 shrink-0">
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie data={slices} dataKey="value" nameKey="name" innerRadius="68%" outerRadius="95%"
                        paddingAngle={2} strokeWidth={0} startAngle={90} endAngle={-270}>
                        {slices.map(s => <Cell key={s.name} fill={s.color} />)}
                      </Pie>
                      <Tooltip {...chartTooltip} />
                    </PieChart>
                  </ResponsiveContainer>
                  <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
                    <span className="text-xl font-semibold tracking-tight text-zinc-50">{summary.block_pct.toFixed(1)}%</span>
                    <span className="text-[10px] font-medium uppercase tracking-[0.08em] text-zinc-500">blocked</span>
                  </div>
                </div>
                <div className="min-w-0 flex-1 space-y-2">
                  {slices.map(s => (
                    <div key={s.name} className="flex items-center gap-2 text-xs">
                      <span className="h-2 w-2 shrink-0 rounded-sm" style={{ background: s.color }} />
                      <span className="min-w-0 flex-1 truncate text-zinc-400">{s.name}</span>
                      <span className="font-mono tabular-nums text-zinc-300">{fmtNum(s.value)}</span>
                      <span className="w-11 shrink-0 text-right font-mono tabular-nums text-zinc-500">
                        {summary.total_queries > 0 ? (s.value / summary.total_queries * 100).toFixed(1) : '0.0'}%
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>

          <div className="grid gap-4 lg:grid-cols-3">
            <Ranked title="Top blocked domains" items={topBlocked} barColor="#8b5cf6" />
            <Ranked title="Top queried domains" items={topQueried} barColor="#34d399" />
            <Ranked title="Most active clients" items={topClients} barColor="#60a5fa" showAlias />
          </div>

          <div className="grid gap-4 lg:grid-cols-3">
            {latency && (
              <div className="card p-4">
                <SectionLabel>Latency</SectionLabel>
                <div className="space-y-1.5">
                  {[['p50', latency.p50_ms], ['p95', latency.p95_ms], ['upstream avg', latency.avg_upstream_ms]].map(([k, v]) => (
                    <div key={k} className="flex items-baseline justify-between text-xs">
                      <span className="text-zinc-500">{k}</span>
                      <span className="font-mono tabular-nums text-zinc-300">{(v as number).toFixed(1)}ms</span>
                    </div>
                  ))}
                  <div className="flex items-baseline justify-between border-t border-white/[0.06] pt-1.5 text-xs">
                    <span className="text-zinc-500">samples</span>
                    <span className="font-mono tabular-nums text-zinc-500">{fmtNum(latency.count)}</span>
                  </div>
                </div>
              </div>
            )}
            <div className="card p-4">
              <SectionLabel>Response codes</SectionLabel>
              {errors.length === 0 ? <div className="py-6 text-center text-xs text-zinc-600">No errors in window</div> : (
                <div className="space-y-1.5">
                  {errors.map(e => (
                    <div key={e.rcode} className="flex items-baseline justify-between gap-3 text-xs">
                      <span className={e.rcode === 0 ? 'text-zinc-400' : 'text-amber-300'}>{e.name || `rcode ${e.rcode}`}</span>
                      <span className="font-mono tabular-nums text-zinc-400">{fmtNum(e.total)}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
            <div className="card p-4">
              <SectionLabel>Per policy group</SectionLabel>
              {groupStats.length === 0 ? <div className="py-6 text-center text-xs text-zinc-600">No groups configured</div> : (
                <div className="space-y-1.5">
                  {groupStats.map(g => (
                    <div key={g.group_id} className="flex items-baseline justify-between gap-3 text-xs">
                      <span className="min-w-0 truncate text-zinc-300">{g.name || 'default'}</span>
                      <span className="shrink-0 font-mono tabular-nums text-zinc-400">{fmtNum(g.total)} · {fmtNum(g.blocked)} blocked · {g.clients} clients</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </>
      )}
      {investigate && <InvestigateModal onClose={() => setInvestigate(false)} />}
    </div>
  )
}

interface LatencyStats { count: number; avg_ms: number; p50_ms: number; p95_ms: number; avg_upstream_ms: number }
interface RCodeStat { rcode: number; name: string; total: number }
interface GroupStat { group_id: number; name: string; total: number; blocked: number; clients: number }

interface DomainReport {
  stats: {
    domain: string; total: number; blocked: number
    first_seen?: string; last_seen?: string
    top_clients: TopItem[]
    rcodes: Record<number, number>
    reasons: Record<string, number>
  }
  engine_lists: Record<number, string>
  engine_excepts: Record<number, string>
  current_rules: { id: number; action: string; domain: string; scope: string }[]
}

function InvestigateModal({ onClose }: { onClose: () => void }) {
  const [domain, setDomain] = useState('')
  const [res, setRes] = useState<DomainReport | null>(null)
  const [err, setErr] = useState('')
  const run = async () => {
    setErr('')
    try { setRes(await api.get<DomainReport>(`/api/v1/stats/domain?domain=${encodeURIComponent(domain)}`)) }
    catch (e) { setErr(e instanceof Error ? e.message : String(e)) }
  }
  return (
    <Modal title="Investigate domain" onClose={onClose} wide>
      <div className="space-y-3">
        <div className="flex gap-2">
          <Field label="Domain">
            <input className="input w-72 font-mono" value={domain} onChange={e => setDomain(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && domain && run()} placeholder="suspicious.example.com" />
          </Field>
          <div className="flex items-end"><button className="btn-primary" disabled={!domain} onClick={run}>Run</button></div>
        </div>
        {err && <ErrorBox error={err} />}
        {res && (
          <div className="space-y-3 text-sm">
            <div className="grid grid-cols-4 gap-3">
              <div><div className="text-xs text-zinc-500">Total queries</div><div className="font-semibold">{fmtNum(res.stats.total)}</div></div>
              <div><div className="text-xs text-zinc-500">Blocked</div><div className="font-semibold">{fmtNum(res.stats.blocked)}</div></div>
              <div><div className="text-xs text-zinc-500">First seen</div><div className="text-xs">{res.stats.first_seen ? fmtTime(res.stats.first_seen) : '—'}</div></div>
              <div><div className="text-xs text-zinc-500">Last seen</div><div className="text-xs">{res.stats.last_seen ? fmtTime(res.stats.last_seen) : '—'}</div></div>
            </div>
            {Object.keys(res.stats.reasons ?? {}).length > 0 && (
              <div>
                <div className="mb-1 text-xs font-medium text-zinc-400">Decision reasons</div>
                {Object.entries(res.stats.reasons).map(([r, n]) => (
                  <div key={r} className="flex justify-between text-xs"><span className="text-zinc-400">{r}</span><span className="font-mono">{n}</span></div>
                ))}
              </div>
            )}
            {(res.current_rules ?? []).length > 0 && (
              <div>
                <div className="mb-1 text-xs font-medium text-zinc-400">Matching custom rules</div>
                {res.current_rules.map(r => (
                  <div key={r.id} className="text-xs"><Badge tone={r.action === 'block' ? 'bad' : 'ok'}>{r.action}</Badge>{' '}
                    <span className="font-mono">{r.scope === 'tree' ? '*.' : ''}{r.domain}</span></div>
                ))}
              </div>
            )}
            <div className="grid grid-cols-2 gap-3 text-xs">
              <div>
                <div className="mb-1 font-medium text-zinc-400">In blocklists</div>
                {Object.keys(res.engine_lists ?? {}).length === 0 ? <div className="text-zinc-600">none</div> :
                  Object.entries(res.engine_lists).map(([id, d]) => <div key={id} className="font-mono">list #{id} via {d}</div>)}
              </div>
              <div>
                <div className="mb-1 font-medium text-zinc-400">Exceptions</div>
                {Object.keys(res.engine_excepts ?? {}).length === 0 ? <div className="text-zinc-600">none</div> :
                  Object.entries(res.engine_excepts).map(([id, d]) => <div key={id} className="font-mono">list #{id} via {d}</div>)}
              </div>
            </div>
            {(res.stats.top_clients ?? []).length > 0 && (
              <div>
                <div className="mb-1 text-xs font-medium text-zinc-400">Top clients querying it</div>
                {res.stats.top_clients.map(c => (
                  <div key={c.value} className="flex justify-between text-xs">
                    <span className="font-mono">{c.alias || c.value}</span><span className="text-zinc-500">{c.total}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </div>
    </Modal>
  )
}

function Ranked({ title, items, barColor, showAlias }: { title: string; items: TopItem[]; barColor: string; showAlias?: boolean }) {
  return (
    <div className="card p-4">
      <SectionLabel>{title}</SectionLabel>
      <RankList items={items} barColor={barColor} showAlias={showAlias} empty="No data" />
    </div>
  )
}
