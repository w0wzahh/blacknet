import { useCallback, useEffect, useRef, useState } from 'react'
import { Pause, Play, Download, Search } from 'lucide-react'
import { api, fmtTime, fmtTimeShort } from '../lib/api'
import { QueryRow } from '../lib/types'
import { Badge, ErrorBox, PageHeader, StatusDot } from '../components/ui'

const QTYPES = ['', 'A', 'AAAA', 'CNAME', 'MX', 'TXT', 'PTR', 'SRV', 'NS', 'HTTPS']
const QTYPE_IDS: Record<string, number> = { A: 1, NS: 2, CNAME: 5, PTR: 12, MX: 15, TXT: 16, AAAA: 28, SRV: 33, HTTPS: 65 }

export function QueryLog() {
  const [rows, setRows] = useState<QueryRow[]>([])
  const [total, setTotal] = useState(0)
  const [pages, setPages] = useState(0)
  const [page, setPage] = useState(1)
  const [dropped, setDropped] = useState(0)
  const [err, setErr] = useState<unknown>(null)

  const [domain, setDomain] = useState('')
  const [client, setClient] = useState('')
  const [blocked, setBlocked] = useState('')
  const [qtype, setQtype] = useState('')
  const [live, setLive] = useState(true)
  const esRef = useRef<EventSource | null>(null)

  const load = useCallback(async (p = page) => {
    try {
      const params = new URLSearchParams()
      if (domain) params.set('domain', domain)
      if (client) params.set('client', client)
      if (blocked) params.set('blocked', blocked)
      if (qtype) params.set('qtype', String(QTYPE_IDS[qtype]))
      params.set('page', String(p))
      params.set('per_page', '100')
      const res = await api.get<{ items: QueryRow[]; total: number; pages: number; dropped_events: number }>(
        '/api/v1/queries?' + params)
      setRows(res.items ?? []); setTotal(res.total); setPages(res.pages); setDropped(res.dropped_events)
      setErr(null)
    } catch (e) { setErr(e) }
  }, [page, domain, client, blocked, qtype])

  useEffect(() => { load(page) }, [page])

  // Live tail via SSE.
  useEffect(() => {
    if (!live) { esRef.current?.close(); esRef.current = null; return }
    const es = new EventSource('/api/v1/queries/live')
    esRef.current = es
    es.onmessage = (m) => {
      try {
        const ev = JSON.parse(m.data) as QueryRow
        if (page === 1) setRows(prev => [ev, ...prev].slice(0, 100))
      } catch { /* heartbeat */ }
    }
    return () => { es.close(); esRef.current = null }
  }, [live, page])

  const exportCSV = () => {
    const params = new URLSearchParams()
    if (domain) params.set('domain', domain)
    if (client) params.set('client', client)
    if (blocked) params.set('blocked', blocked)
    window.open('/api/v1/queries/export?' + params, '_blank')
  }

  return (
    <div className="space-y-4">
      <PageHeader title="Query Log" desc="Every DNS query the resolver answered — live tail included.">
        <div className="flex items-center gap-2">
          <Badge tone={live ? 'ok' : 'muted'}>
            <StatusDot tone={live ? 'ok' : 'muted'} /><span className="ml-1">{live ? 'live' : 'paused'}</span>
          </Badge>
          {dropped > 0 && <Badge tone="warn">{dropped} events dropped</Badge>}
          <button className="btn-ghost" onClick={() => setLive(v => !v)}>
            {live ? <><Pause className="h-3.5 w-3.5" /> Pause</> : <><Play className="h-3.5 w-3.5" /> Resume</>}
          </button>
          <button className="btn-ghost" onClick={exportCSV}><Download className="h-3.5 w-3.5" /> CSV</button>
        </div>
      </PageHeader>

      <div className="card flex flex-wrap items-center gap-2 p-3">
        <div className="relative">
          <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-zinc-500" />
          <input className="input pl-8 w-56" placeholder="Search domain…" value={domain}
            onChange={e => setDomain(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && (setPage(1), load(1))} />
        </div>
        <input className="input w-40" placeholder="Client IP" value={client}
          onChange={e => setClient(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && (setPage(1), load(1))} />
        <select className="input" value={blocked} onChange={e => { setBlocked(e.target.value); }}>
          <option value="">All decisions</option>
          <option value="true">Blocked</option>
          <option value="false">Allowed</option>
        </select>
        <select className="input" value={qtype} onChange={e => setQtype(e.target.value)}>
          {QTYPES.map(t => <option key={t} value={t}>{t || 'All types'}</option>)}
        </select>
        <button className="btn-primary" onClick={() => { setPage(1); load(1) }}>Apply</button>
        <button className="btn-ghost" onClick={() => { setDomain(''); setClient(''); setBlocked(''); setQtype(''); setPage(1); setTimeout(() => load(1), 0) }}>Clear</button>
      </div>

      <ErrorBox error={err} />

      <div className="card overflow-x-auto">
        <table className="w-full min-w-[760px]">
          <thead>
            <tr>
              <th className="th">Time</th>
              <th className="th">Client</th>
              <th className="th">Domain</th>
              <th className="th">Type</th>
              <th className="th">Decision</th>
              <th className="th">Reason</th>
              <th className="th">Code</th>
              <th className="th text-right">ms</th>
            </tr>
          </thead>
          <tbody>
            {rows.length === 0 && (
              <tr><td className="td py-10 text-center text-zinc-600" colSpan={8}>No queries recorded yet</td></tr>
            )}
            {rows.map(q => (
              <tr key={q.id} className="hover:bg-zinc-800/30">
                <td className="td whitespace-nowrap text-xs text-zinc-500">{fmtTime(q.time)}</td>
                <td className="td font-mono text-xs">{q.alias || q.client_ip}</td>
                <td className="td max-w-[240px] truncate font-mono text-xs">{q.domain}</td>
                <td className="td text-xs text-zinc-500">{q.qtype_name || q.qtype}</td>
                <td className="td">
                  {q.blocked ? <Badge tone="bad">blocked</Badge> : q.cached ? <Badge tone="accent">cached</Badge> : <Badge tone="muted">allowed</Badge>}
                </td>
                <td className="td max-w-[180px] truncate text-xs text-zinc-500" title={q.reason}>{q.reason}</td>
                <td className="td text-xs text-zinc-500">{q.rcode_name || q.rcode}</td>
                <td className="td text-right tabular-nums text-xs text-zinc-500">{q.latency_ms?.toFixed(1)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="flex items-center justify-between text-xs text-zinc-500">
        <span>{total.toLocaleString()} total</span>
        <div className="flex items-center gap-2">
          <button className="btn-ghost" disabled={page <= 1} onClick={() => setPage(p => p - 1)}>Prev</button>
          <span>page {page} / {Math.max(pages, 1)}</span>
          <button className="btn-ghost" disabled={page >= pages} onClick={() => setPage(p => p + 1)}>Next</button>
        </div>
      </div>
    </div>
  )
}
