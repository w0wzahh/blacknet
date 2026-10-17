import { useEffect, useState } from 'react'
import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid } from 'recharts'
import { api, fmtNum, fmtTime, fmtTimeShort } from '../lib/api'
import { Status, Summary, Bucket, TopItem, QueryRow } from '../lib/types'
import { StatCard, Badge, EmptyState, Loading, ErrorBox, Toggle, chartTooltip } from '../components/ui'

export function Overview() {
  const [status, setStatus] = useState<Status | null>(null)
  const [summary, setSummary] = useState<Summary | null>(null)
  const [series, setSeries] = useState<Bucket[]>([])
  const [topBlocked, setTopBlocked] = useState<TopItem[]>([])
  const [topClients, setTopClients] = useState<TopItem[]>([])
  const [recentBlocked, setRecentBlocked] = useState<QueryRow[]>([])
  const [err, setErr] = useState<unknown>(null)
  const [confirmOff, setConfirmOff] = useState(false)

  const load = async () => {
    try {
      const [st, sum, ts, tb, tc, rb] = await Promise.all([
        api.get<Status>('/api/v1/status'),
        api.get<Summary>('/api/v1/stats/summary?window=24h'),
        api.get<Bucket[]>('/api/v1/stats/timeseries?window=24h&buckets=48'),
        api.get<TopItem[]>('/api/v1/stats/top-domains?blocked=true&limit=8&window=24h'),
        api.get<TopItem[]>('/api/v1/stats/top-clients?limit=8&window=24h'),
        api.get<{ items: QueryRow[] }>('/api/v1/queries?blocked=true&per_page=8'),
      ])
      setStatus(st); setSummary(sum); setSeries(ts ?? [])
      setTopBlocked(tb ?? []); setTopClients(tc ?? []); setRecentBlocked(rb.items ?? [])
      setErr(null)
    } catch (e) { setErr(e) }
  }

  useEffect(() => {
    load()
    const t = setInterval(load, 15000)
    return () => clearInterval(t)
  }, [])

  const toggleProtection = async (on: boolean) => {
    try {
      await api.post(`/api/v1/protection/${on ? 'enable' : 'disable'}${on ? '' : '?confirm=true'}`)
      setConfirmOff(false)
      load()
    } catch (e) { setErr(e) }
  }

  if (!status || !summary) return <Loading />
  const healthy = status.upstreams_healthy > 0

  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between">
        <h1 className="text-lg font-semibold text-zinc-100">Overview</h1>
        <div className="flex items-center gap-3">
          <Badge tone={status.protection_enabled ? 'ok' : 'bad'}>
            {status.protection_enabled ? 'Protection on' : 'Protection off'}
          </Badge>
          <Badge tone={healthy ? 'ok' : 'bad'}>
            DNS {healthy ? 'healthy' : 'degraded'}
          </Badge>
          <div className="flex items-center gap-2 text-xs text-zinc-500">
            <Toggle on={status.protection_enabled} onChange={(v) => v ? toggleProtection(true) : setConfirmOff(true)} />
            filtering
          </div>
        </div>
      </div>

      {confirmOff && (
        <div className="card border-amber-800/60 bg-amber-950/30 p-4 flex items-center justify-between">
          <div className="text-sm text-amber-200">
            Disable filtering? All queries will resolve without blocking until re-enabled. Rules and lists are preserved.
          </div>
          <div className="flex gap-2">
            <button className="btn-danger" onClick={() => toggleProtection(false)}>Disable</button>
            <button className="btn-ghost" onClick={() => setConfirmOff(false)}>Cancel</button>
          </div>
        </div>
      )}

      <ErrorBox error={err} />

      <div className="grid grid-cols-2 gap-3 md:grid-cols-4 xl:grid-cols-8">
        <StatCard label="Queries (24h)" value={fmtNum(summary.total_queries)} />
        <StatCard label="Blocked" value={fmtNum(summary.blocked_queries)} accent />
        <StatCard label="Block rate" value={summary.block_pct.toFixed(1) + '%'} />
        <StatCard label="Allowed" value={fmtNum(summary.allowed_queries)} />
        <StatCard label="Cached" value={fmtNum(summary.cached_queries)} sub={`${status.cache_hit_rate.toFixed(0)}% hit`} />
        <StatCard label="Clients" value={status.known_clients} />
        <StatCard label="Lists" value={status.active_blocklists} sub={`${fmtNum(status.blocklist_domains)} domains`} />
        <StatCard label="Upstreams" value={`${status.upstreams_healthy}/${status.upstreams_total}`} sub="healthy" />
      </div>

      {summary.total_queries === 0 ? (
        <EmptyState
          title="No DNS queries yet"
          hint="Point a device or your router at this server's DNS address, or run: blacknet test-dns example.com"
        />
      ) : (
        <div className="card p-4">
          <div className="mb-3 text-xs font-medium uppercase tracking-wide text-zinc-500">Queries — last 24h</div>
          <div className="h-48">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={series} margin={{ top: 4, right: 4, bottom: 0, left: -18 }}>
                <defs>
                  <linearGradient id="gT" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#71717a" stopOpacity={0.35} />
                    <stop offset="100%" stopColor="#71717a" stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="gB" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#8b5cf6" stopOpacity={0.4} />
                    <stop offset="100%" stopColor="#8b5cf6" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid stroke="#27272a" vertical={false} />
                <XAxis dataKey="ts" tickFormatter={t => fmtTimeShort(t)} tick={{ fontSize: 10, fill: '#71717a' }} tickLine={false} axisLine={false} minTickGap={40} />
                <YAxis tick={{ fontSize: 10, fill: '#71717a' }} tickLine={false} axisLine={false} allowDecimals={false} />
                <Tooltip
                  {...chartTooltip}
                  labelFormatter={l => fmtTime(l as string)}
                />
                <Area type="monotone" dataKey="total" stroke="#a1a1aa" fill="url(#gT)" strokeWidth={1.5} name="Total" />
                <Area type="monotone" dataKey="blocked" stroke="#8b5cf6" fill="url(#gB)" strokeWidth={1.5} name="Blocked" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>
      )}

      <div className="grid gap-4 lg:grid-cols-3">
        <div className="card p-4">
          <div className="mb-2 text-xs font-medium uppercase tracking-wide text-zinc-500">Top blocked domains</div>
          {topBlocked.length === 0 ? <div className="py-6 text-center text-xs text-zinc-600">Nothing blocked yet</div> : (
            <table className="w-full">
              <tbody>
                {topBlocked.map(d => (
                  <tr key={d.value}>
                    <td className="td truncate font-mono text-xs" style={{ maxWidth: 180 }}>{d.value}</td>
                    <td className="td text-right text-zinc-500 w-14">{fmtNum(d.total)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
        <div className="card p-4">
          <div className="mb-2 text-xs font-medium uppercase tracking-wide text-zinc-500">Top clients</div>
          {topClients.length === 0 ? <div className="py-6 text-center text-xs text-zinc-600">No clients yet</div> : (
            <table className="w-full">
              <tbody>
                {topClients.map(c => (
                  <tr key={c.value}>
                    <td className="td truncate text-xs" style={{ maxWidth: 180 }}>
                      {c.alias || c.value}
                      {c.alias && <span className="ml-1.5 text-zinc-600 font-mono">{c.value}</span>}
                    </td>
                    <td className="td text-right text-zinc-500 w-14">{fmtNum(c.total)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
        <div className="card p-4">
          <div className="mb-2 text-xs font-medium uppercase tracking-wide text-zinc-500">Recent blocks</div>
          {recentBlocked.length === 0 ? <div className="py-6 text-center text-xs text-zinc-600">No blocked queries yet</div> : (
            <table className="w-full">
              <tbody>
                {recentBlocked.map(q => (
                  <tr key={q.id}>
                    <td className="td truncate font-mono text-xs" style={{ maxWidth: 140 }}>{q.domain}</td>
                    <td className="td text-right text-xs text-zinc-600 w-20">{fmtTimeShort(q.time)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </div>
  )
}
