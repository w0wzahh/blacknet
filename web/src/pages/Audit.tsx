import { useEffect, useState } from 'react'
import { Download, Search, ChevronLeft, ChevronRight } from 'lucide-react'
import { api, fmtTime } from '../lib/api'
import { AuditEntry } from '../lib/types'
import { Badge, EmptyState, ErrorBox, Loading, Field, PageHeader } from '../components/ui'

interface AuditResp { items: AuditEntry[]; total: number; page: number; per_page: number }

const PER = 50

export function Audit() {
  const [data, setData] = useState<AuditResp | null>(null)
  const [err, setErr] = useState<unknown>(null)
  const [action, setAction] = useState('')
  const [actor, setActor] = useState('')
  const [page, setPage] = useState(1)

  const load = () => {
    const q = new URLSearchParams({ page: String(page), per_page: String(PER) })
    if (action) q.set('action', action)
    if (actor) q.set('actor', actor)
    api.get<AuditResp>(`/api/v1/audit/log?${q}`).then(setData).catch(setErr)
  }
  useEffect(() => { load() }, [page])

  const pages = data ? Math.max(1, Math.ceil(data.total / data.per_page)) : 1

  return (
    <div className="space-y-4">
      <PageHeader title="Audit Log" desc="Every change made through the dashboard or API, recorded.">
        <button className="btn-ghost" onClick={() => window.open('/api/v1/audit/export', '_blank')}>
          <Download className="h-3.5 w-3.5" /> Export CSV
        </button>
      </PageHeader>
      <ErrorBox error={err} />

      <div className="card flex flex-wrap items-end gap-3 p-3">
        <Field label="Action contains">
          <input className="input w-56" value={action} onChange={e => setAction(e.target.value)} placeholder="rule.create" />
        </Field>
        <Field label="Actor">
          <input className="input w-40" value={actor} onChange={e => setActor(e.target.value)} placeholder="admin" />
        </Field>
        <button className="btn-primary" onClick={() => { setPage(1); load() }}>
          <Search className="h-3.5 w-3.5" /> Filter
        </button>
        {data && <span className="ml-auto text-xs text-zinc-600">{data.total} events</span>}
      </div>

      {!data ? <Loading /> : data.items.length === 0 ? (
        <EmptyState title="No audit events" hint="Every settings change, rule edit, enforcement op and login is recorded here." />
      ) : (
        <div className="card overflow-x-auto">
          <table className="w-full min-w-[760px]">
            <thead><tr>
              <th className="th">Time (UTC)</th><th className="th">Actor</th><th className="th">Action</th>
              <th className="th">Resource</th><th className="th">Result</th><th className="th">Detail</th>
            </tr></thead>
            <tbody>
              {data.items.map(e => (
                <tr key={e.id} className="hover:bg-zinc-800/30">
                  <td className="td text-xs text-zinc-500 whitespace-nowrap">{fmtTime(e.ts)}</td>
                  <td className="td text-xs">{e.actor || 'system'}</td>
                  <td className="td"><Badge tone={e.result === 'ok' ? 'muted' : 'bad'}>{e.action}</Badge></td>
                  <td className="td font-mono text-xs text-zinc-400">{e.resource || '—'}</td>
                  <td className="td text-xs">{e.result === 'ok' ? <span className="text-emerald-400">ok</span> : <span className="text-red-400">{e.result}</span>}</td>
                  <td className="td max-w-[280px] truncate text-xs text-zinc-500" title={e.detail}>{e.detail || '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {data && pages > 1 && (
        <div className="flex items-center justify-center gap-3">
          <button className="btn-ghost px-2!" disabled={page <= 1} onClick={() => setPage(page - 1)}><ChevronLeft className="h-4 w-4" /></button>
          <span className="text-xs text-zinc-500">page {data.page} of {pages}</span>
          <button className="btn-ghost px-2!" disabled={page >= pages} onClick={() => setPage(page + 1)}><ChevronRight className="h-4 w-4" /></button>
        </div>
      )}
    </div>
  )
}
