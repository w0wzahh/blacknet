import { useEffect, useState } from 'react'
import {
  AreaChart, Area, BarChart, Bar, PieChart, Pie, Cell,
  XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid, Legend,
} from 'recharts'
import { api, fmtNum, fmtTime, fmtTimeShort } from '../lib/api'
import { Bucket, TopItem, Summary, Status } from '../lib/types'
import { EmptyState, ErrorBox, Loading } from '../components/ui'

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
  const [err, setErr] = useState<unknown>(null)

  const load = async () => {
    try {
      const buckets = win === '1h' ? 60 : win === '24h' ? 48 : win === '7d' ? 84 : 120
      const [ts, sum, st, tb, tq, tc] = await Promise.all([
        api.get<Bucket[]>(`/api/v1/stats/timeseries?window=${win}&buckets=${buckets}`),
        api.get<Summary>(`/api/v1/stats/summary?window=${win}`),
        api.get<Status>('/api/v1/status'),
        api.get<TopItem[]>(`/api/v1/stats/top-domains?blocked=true&limit=10&window=${win}`),
        api.get<TopItem[]>(`/api/v1/stats/top-domains?limit=10&window=${win}`),
        api.get<TopItem[]>(`/api/v1/stats/top-clients?limit=10&window=${win}`),
      ])
      setSeries(ts); setSummary(sum); setStatus(st)
      setTopBlocked(tb); setTopQueried(tq); setTopClients(tc)
      setErr(null)
    } catch (e) { setErr(e) }
  }
  useEffect(() => { load() }, [win])

  if (!summary || !status) return <Loading />
  const pie = [
    { name: 'Allowed', value: summary.allowed_queries },
    { name: 'Blocked', value: summary.blocked_queries },
    { name: 'Cached', value: Math.min(summary.cached_queries, summary.allowed_queries) },
  ]

  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between">
        <h1 className="text-lg font-semibold text-zinc-100">Analytics</h1>
        <div className="flex gap-1">
          {WINDOWS.map(w => (
            <button key={w.v} onClick={() => setWin(w.v)}
              className={`rounded-md px-2.5 py-1 text-xs font-medium ${win === w.v ? 'bg-violet-600 text-white' : 'text-zinc-400 hover:bg-zinc-800'}`}>
              {w.label}
            </button>
          ))}
        </div>
      </div>
      <ErrorBox error={err} />

      {summary.total_queries === 0 ? (
        <EmptyState title="No data in this window" hint="Analytics are computed from real logged queries. Generate some DNS traffic first." />
      ) : (
        <>
          <div className="grid gap-4 lg:grid-cols-3">
            <div className="card p-4 lg:col-span-2">
              <div className="mb-2 text-xs font-medium uppercase tracking-wide text-zinc-500">Queries over time</div>
              <div className="h-56">
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={series} margin={{ top: 4, right: 4, bottom: 0, left: -18 }}>
                    <CartesianGrid stroke="#27272a" vertical={false} />
                    <XAxis dataKey="ts" tickFormatter={t => fmtTimeShort(t)} tick={{ fontSize: 10, fill: '#71717a' }} tickLine={false} axisLine={false} minTickGap={40} />
                    <YAxis tick={{ fontSize: 10, fill: '#71717a' }} tickLine={false} axisLine={false} allowDecimals={false} />
                    <Tooltip contentStyle={{ background: '#18181b', border: '1px solid #3f3f46', borderRadius: 8, fontSize: 12 }} labelFormatter={l => fmtTime(l as string)} />
                    <Legend wrapperStyle={{ fontSize: 11 }} />
                    <Area type="monotone" dataKey="allowed" stackId="1" stroke="#34d399" fill="#34d399" fillOpacity={0.25} name="Allowed" />
                    <Area type="monotone" dataKey="blocked" stackId="1" stroke="#8b5cf6" fill="#8b5cf6" fillOpacity={0.35} name="Blocked" />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            </div>
            <div className="card p-4">
              <div className="mb-2 text-xs font-medium uppercase tracking-wide text-zinc-500">Decision share</div>
              <div className="h-56">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie data={pie} dataKey="value" innerRadius={52} outerRadius={78} paddingAngle={2} strokeWidth={0}>
                      <Cell fill="#34d399" fillOpacity={0.7} />
                      <Cell fill="#8b5cf6" />
                      <Cell fill="#71717a" fillOpacity={0.6} />
                    </Pie>
                    <Tooltip contentStyle={{ background: '#18181b', border: '1px solid #3f3f46', borderRadius: 8, fontSize: 12 }} />
                    <Legend wrapperStyle={{ fontSize: 11 }} />
                  </PieChart>
                </ResponsiveContainer>
              </div>
            </div>
          </div>

          <div className="grid gap-4 lg:grid-cols-3">
            <Ranked title="Top blocked domains" items={topBlocked} barColor="#8b5cf6" />
            <Ranked title="Top queried domains" items={topQueried} barColor="#34d399" />
            <Ranked title="Most active clients" items={topClients} barColor="#60a5fa" showAlias />
          </div>

          <div className="card p-4 grid grid-cols-2 gap-3 sm:grid-cols-4 text-sm">
            <div><div className="text-xs text-zinc-500">Unique domains</div><div className="text-lg font-semibold">{fmtNum(summary.unique_domains)}</div></div>
            <div><div className="text-xs text-zinc-500">Active clients</div><div className="text-lg font-semibold">{summary.active_clients}</div></div>
            <div><div className="text-xs text-zinc-500">Avg latency</div><div className="text-lg font-semibold">{summary.avg_latency_ms.toFixed(1)}ms</div></div>
            <div><div className="text-xs text-zinc-500">Cache hit rate</div><div className="text-lg font-semibold">{status.cache_hit_rate.toFixed(1)}%</div></div>
          </div>
        </>
      )}
    </div>
  )
}

function Ranked({ title, items, barColor, showAlias }: { title: string; items: TopItem[]; barColor: string; showAlias?: boolean }) {
  const data = items.map(i => ({ name: showAlias && i.alias ? i.alias : i.value, total: i.total }))
  return (
    <div className="card p-4">
      <div className="mb-2 text-xs font-medium uppercase tracking-wide text-zinc-500">{title}</div>
      {items.length === 0 ? <div className="py-8 text-center text-xs text-zinc-600">No data</div> : (
        <div className="h-56">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={data} layout="vertical" margin={{ top: 0, right: 8, bottom: 0, left: 8 }}>
              <XAxis type="number" hide />
              <YAxis type="category" dataKey="name" width={110} tick={{ fontSize: 10, fill: '#a1a1aa' }} tickLine={false} axisLine={false}
                tickFormatter={(v: string) => v.length > 18 ? v.slice(0, 17) + '…' : v} />
              <Tooltip contentStyle={{ background: '#18181b', border: '1px solid #3f3f46', borderRadius: 8, fontSize: 12 }} />
              <Bar dataKey="total" fill={barColor} fillOpacity={0.75} radius={[0, 3, 3, 0]} barSize={10} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      )}
    </div>
  )
}
