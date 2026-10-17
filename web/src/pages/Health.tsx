import { useEffect, useState } from 'react'
import { RefreshCw, Download, CheckCircle2, XCircle, AlertCircle } from 'lucide-react'
import { api, fmtNum, fmtTime } from '../lib/api'
import { Badge, ErrorBox, Loading, PageHeader } from '../components/ui'

interface HealthResp {
  ok: boolean
  version: string
  time: string
  checks: Record<string, any>
}

interface ProtectionResp {
  configured: { dns_listen: string[]; trusted_cidrs: string[]; protection: boolean }
  observed: { known_clients: number; unmanaged_devices: number; host_interfaces: any[]; query_log_dropped: number }
  enforced: { ts: string; integration: string; action: string; status: string } | null
  notes: string[]
}

function toneFor(ok: boolean | undefined) {
  return ok === undefined ? 'muted' : ok ? 'ok' : 'bad'
}

function CheckCard({ name, data }: { name: string; data: any }) {
  const ok: boolean | undefined = data?.ok !== undefined
    ? !!data.ok
    : data?.healthy !== undefined
      ? data.healthy > 0
      : data?.failing !== undefined
        ? data.failing === 0 && data.never_refreshed === 0
        : undefined
  const Icon = ok === true ? CheckCircle2 : ok === false ? XCircle : AlertCircle
  const color = ok === true ? 'text-emerald-400' : ok === false ? 'text-red-400' : 'text-amber-400'
  return (
    <div className="card p-4">
      <div className="flex items-center gap-2">
        <Icon className={`h-4 w-4 ${color}`} />
        <span className="text-sm font-medium capitalize text-zinc-200">{name.replace(/_/g, ' ')}</span>
      </div>
      <div className="mt-2 space-y-0.5">
        {Object.entries(data ?? {}).map(([k, v]) => (
          <div key={k} className="flex justify-between gap-3 text-xs">
            <span className="text-zinc-500">{k.replace(/_/g, ' ')}</span>
            <span className="truncate font-mono text-zinc-300" title={String(v)}>
              {typeof v === 'boolean' ? (v ? 'yes' : 'no') : Array.isArray(v) ? v.join(', ') : String(v ?? '—')}
            </span>
          </div>
        ))}
      </div>
    </div>
  )
}

export function Health() {
  const [h, setH] = useState<HealthResp | null>(null)
  const [prot, setProt] = useState<ProtectionResp | null>(null)
  const [err, setErr] = useState<unknown>(null)
  const [at, setAt] = useState('')

  const load = () => {
    api.get<HealthResp>('/api/v1/system/health').then(r => { setH(r); setAt(new Date().toLocaleTimeString()) }).catch(setErr)
    api.get<ProtectionResp>('/api/v1/network/protection').then(setProt).catch(() => {})
  }
  useEffect(() => { load() }, [])

  if (!h) return err ? <ErrorBox error={err} /> : <Loading />

  return (
    <div className="space-y-4">
      <PageHeader title="System Health" desc={`v${h.version} · checked ${at}`}>
        <div className="flex gap-2">
          <button className="btn-ghost" onClick={load}><RefreshCw className="h-3.5 w-3.5" /> Refresh</button>
          <button className="btn-ghost" onClick={() => window.open('/api/v1/diagnostics/export', '_blank')}>
            <Download className="h-3.5 w-3.5" /> Diagnostic bundle
          </button>
        </div>
      </PageHeader>

      <div className={`card flex items-center gap-3 p-4 ${h.ok ? 'border-emerald-800/50' : 'border-red-800/50'}`}>
        {h.ok ? <CheckCircle2 className="h-5 w-5 text-emerald-400" /> : <XCircle className="h-5 w-5 text-red-400" />}
        <div>
          <div className="text-sm font-medium text-zinc-100">{h.ok ? 'All systems nominal' : 'Something needs attention'}</div>
          <div className="text-xs text-zinc-500">Server time {fmtTime(h.time)} UTC</div>
        </div>
      </div>

      <ErrorBox error={err} />

      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
        {Object.entries(h.checks).map(([k, v]) => <CheckCard key={k} name={k} data={v} />)}
      </div>

      {prot && (
        <>
          <h2 className="pt-2 text-sm font-semibold tracking-tight text-zinc-100">Network protection posture</h2>
          <div className="card space-y-3 p-4">
            <div className="grid gap-3 sm:grid-cols-3">
              <div>
                <div className="text-[11px] font-medium uppercase tracking-[0.08em] text-zinc-500">Listening</div>
                <div className="mt-1 font-mono text-xs text-zinc-300">{prot.configured.dns_listen.join(', ')}</div>
              </div>
              <div>
                <div className="text-[11px] font-medium uppercase tracking-[0.08em] text-zinc-500">Known clients</div>
                <div className="mt-1 text-sm text-zinc-200">{fmtNum(prot.observed.known_clients)}</div>
              </div>
              <div>
                <div className="text-[11px] font-medium uppercase tracking-[0.08em] text-zinc-500">Unmanaged devices seen</div>
                <div className="mt-1 text-sm text-zinc-200">
                  {prot.observed.unmanaged_devices > 0
                    ? <Badge tone="warn">{prot.observed.unmanaged_devices}</Badge>
                    : <Badge tone="ok">0</Badge>}
                </div>
              </div>
            </div>
            <div>
              <div className="text-[11px] font-medium uppercase tracking-[0.08em] text-zinc-500">Router enforcement</div>
              <div className="mt-1 text-sm text-zinc-200">
                {prot.enforced
                  ? <Badge tone="ok">{prot.enforced.integration} · {prot.enforced.status} · {fmtTime(prot.enforced.ts)}</Badge>
                  : <Badge tone="warn">not verified — devices may bypass filtering</Badge>}
              </div>
            </div>
            {prot.observed.query_log_dropped > 0 && (
              <div className="text-xs text-amber-400">
                {fmtNum(prot.observed.query_log_dropped)} query events were dropped (writer couldn't keep up).
              </div>
            )}
            <ul className="space-y-1 border-t border-zinc-800 pt-2">
              {prot.notes.map((n, i) => <li key={i} className="text-xs text-zinc-500">• {n}</li>)}
            </ul>
          </div>
        </>
      )}
    </div>
  )
}
