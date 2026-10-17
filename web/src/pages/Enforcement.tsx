import { useEffect, useState } from 'react'
import { Play, RotateCcw, ShieldCheck, AlertTriangle, Eye } from 'lucide-react'
import { api, fmtTime } from '../lib/api'
import { Integration, EnforcementPlan, EnforcementOp } from '../lib/types'
import { Badge, EmptyState, ErrorBox, Loading, Modal, Field, PageHeader } from '../components/ui'

export function Enforcement() {
  const [integrations, setIntegrations] = useState<Integration[] | null>(null)
  const [ops, setOps] = useState<EnforcementOp[]>([])
  const [err, setErr] = useState<unknown>(null)
  const [selected, setSelected] = useState<Integration | null>(null)

  const load = () => {
    api.get<Integration[]>('/api/v1/enforcement/integrations').then(r => setIntegrations(r ?? [])).catch(setErr)
    api.get<EnforcementOp[]>('/api/v1/enforcement/operations?limit=50').then(r => setOps(r ?? [])).catch(() => {})
  }
  useEffect(() => { load() }, [])

  const statusTone = (s: string) =>
    s === 'verified' || s === 'applied' ? 'ok' : s === 'failed' ? 'bad' : s === 'rolled_back' ? 'warn' : 'muted'

  if (!integrations) return err ? <ErrorBox error={err} /> : <Loading />

  return (
    <div className="space-y-4">
      <PageHeader title="Router Enforcement" desc="Make the router send all DNS through Blacknet — every change previews first and can be rolled back." />
      <ErrorBox error={err} />

      <div className="grid gap-3 sm:grid-cols-2">
        {integrations.map(i => (
          <div key={i.id} className="card p-4">
            <div className="flex items-center justify-between">
              <span className="font-medium text-zinc-100">{i.name}</span>
              {i.available
                ? (i.verified ? <Badge tone="ok">verified</Badge> : <Badge tone="accent">available</Badge>)
                : <Badge tone="muted">unavailable</Badge>}
            </div>
            {i.reason && <div className="mt-1 text-xs text-zinc-500">{i.reason}</div>}
            {i.last_error && <div className="mt-1 text-xs text-red-400">{i.last_error}</div>}
            {i.notes && <div className="mt-1 text-xs text-zinc-600">{i.notes}</div>}
            <div className="mt-3">
              <button className="btn-primary" disabled={!i.available} onClick={() => setSelected(i)}>
                Configure
              </button>
            </div>
          </div>
        ))}
      </div>

      <h2 className="pt-2 text-sm font-semibold text-zinc-200">Operation history</h2>
      {ops.length === 0 ? (
        <EmptyState title="No enforcement operations yet" hint="Applied changes and rollbacks are recorded here with their full plan." />
      ) : (
        <div className="card overflow-x-auto">
          <table className="w-full min-w-[720px]">
            <thead><tr>
              <th className="th">Time</th><th className="th">Integration</th><th className="th">Action</th>
              <th className="th">Status</th><th className="th">Result</th><th className="th" />
            </tr></thead>
            <tbody>
              {ops.map(o => (
                <OpRow key={o.id} op={o} onDone={load} statusTone={statusTone} />
              ))}
            </tbody>
          </table>
        </div>
      )}

      {selected && <ApplyModal integration={selected} onClose={() => setSelected(null)} onDone={() => { setSelected(null); load() }} />}
    </div>
  )
}

function OpRow({ op, onDone, statusTone }: {
  op: EnforcementOp; onDone: () => void; statusTone: (s: string) => 'ok' | 'bad' | 'warn' | 'muted' | 'accent'
}) {
  const [open, setOpen] = useState(false)
  const [err, setErr] = useState('')
  const rollback = async () => {
    if (!confirm('Roll back this operation? The router configuration will be reverted to the recorded state.')) return
    try {
      await api.post(`/api/v1/enforcement/rollback/${op.id}?confirm=true`, { integration: op.integration })
      onDone()
    } catch (e) { setErr(e instanceof Error ? e.message : String(e)) }
  }
  return (
    <>
      <tr className="hover:bg-zinc-800/30">
        <td className="td text-xs text-zinc-500 whitespace-nowrap">{fmtTime(op.ts)}</td>
        <td className="td text-xs">{op.integration}</td>
        <td className="td text-xs">{op.action}</td>
        <td className="td"><Badge tone={statusTone(op.status)}>{op.status}</Badge></td>
        <td className="td max-w-[260px] truncate text-xs text-zinc-500">{op.result || '—'}</td>
        <td className="td">
          <div className="flex justify-end gap-1">
            <button className="btn-ghost px-2!" title="View plan" onClick={() => setOpen(true)}><Eye className="h-3.5 w-3.5" /></button>
            {(op.status === 'applied' || op.status === 'verified') && (
              <button className="btn-ghost px-2!" title="Roll back" onClick={rollback}><RotateCcw className="h-3.5 w-3.5" /></button>
            )}
          </div>
          {err && <div className="text-xs text-red-400">{err}</div>}
        </td>
      </tr>
      {open && (
        <tr>
          <td colSpan={6} className="td">
            <div className="rounded-md border border-zinc-800 bg-zinc-950/50 p-3">
              <pre className="whitespace-pre-wrap font-mono text-xs text-zinc-300">{op.preview || '(no preview recorded)'}</pre>
            </div>
          </td>
        </tr>
      )}
    </>
  )
}

function ApplyModal({ integration, onClose, onDone }: {
  integration: Integration; onClose: () => void; onDone: () => void
}) {
  const [host, setHost] = useState('')
  const [port, setPort] = useState(22)
  const [username, setUsername] = useState('root')
  const [password, setPassword] = useState('')
  const [action, setAction] = useState('redirect_dns')
  const [plan, setPlan] = useState<EnforcementPlan | null>(null)
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)
  const needsCreds = integration.id !== 'manual'

  const req = () => ({
    integration: integration.id, action,
    host: needsCreds ? host : '', port, username, password,
  })

  const preview = async () => {
    setBusy(true); setErr('')
    try { setPlan(await api.post<EnforcementPlan>('/api/v1/enforcement/preview', req())) }
    catch (e) { setErr(e instanceof Error ? e.message : String(e)) }
    setBusy(false)
  }
  const apply = async () => {
    if (!confirm('Apply this change to the router now?')) return
    setBusy(true); setErr('')
    try {
      await api.post('/api/v1/enforcement/apply?confirm=true', req())
      onDone()
    } catch (e) { setErr(e instanceof Error ? e.message : String(e)); setBusy(false) }
  }

  return (
    <Modal title={`Enforce via ${integration.name}`} onClose={onClose} wide>
      <div className="space-y-3">
        <Field label="Action">
          <select className="input w-full" value={action} onChange={e => { setAction(e.target.value); setPlan(null) }}>
            <option value="redirect_dns">Redirect all DNS to Blacknet</option>
            <option value="block_bypass">Block DNS bypass (DoT/853)</option>
            <option value="dhcp_dns">Advertise Blacknet via DHCP</option>
          </select>
        </Field>
        {needsCreds && (
          <div className="grid grid-cols-3 gap-3">
            <Field label="Router host"><input className="input w-full font-mono" value={host} onChange={e => setHost(e.target.value)} placeholder="192.168.1.1" /></Field>
            <Field label="SSH port"><input className="input w-full font-mono" type="number" value={port} onChange={e => setPort(Number(e.target.value))} /></Field>
            <Field label="User"><input className="input w-full" value={username} onChange={e => setUsername(e.target.value)} /></Field>
          </div>
        )}
        {needsCreds && (
          <Field label="Password" hint="Used once for this operation — never stored.">
            <input className="input w-full" type="password" value={password} onChange={e => setPassword(e.target.value)} />
          </Field>
        )}
        {!plan ? (
          <button className="btn-primary" disabled={busy || (needsCreds && !host)} onClick={preview}>
            <Eye className="h-3.5 w-3.5" /> {busy ? 'Building plan…' : 'Preview plan'}
          </button>
        ) : (
          <div className="space-y-3">
            <div className="rounded-md border border-zinc-800 bg-zinc-950/50 p-3">
              <div className="text-sm text-zinc-200">{plan.summary}</div>
              <pre className="mt-2 max-h-56 overflow-y-auto whitespace-pre-wrap font-mono text-xs text-zinc-400">
                {plan.commands.join('\n')}
              </pre>
            </div>
            {(plan.warnings ?? []).map((w, i) => (
              <div key={i} className="flex items-start gap-2 rounded-md border border-amber-800/60 bg-amber-950/40 px-3 py-2 text-xs text-amber-300">
                <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" /> {w}
              </div>
            ))}
            {err && <ErrorBox error={err} />}
            <div className="flex justify-end gap-2">
              <button className="btn-ghost" onClick={onClose}>Cancel</button>
              <button className="btn-primary" disabled={busy} onClick={apply}>
                {integration.id === 'manual' ? <ShieldCheck className="h-3.5 w-3.5" /> : <Play className="h-3.5 w-3.5" />}
                {integration.id === 'manual' ? 'Record as done' : 'Apply now'}
              </button>
            </div>
          </div>
        )}
        {err && !plan && <ErrorBox error={err} />}
      </div>
    </Modal>
  )
}
