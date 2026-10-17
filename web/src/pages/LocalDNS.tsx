import { useEffect, useState } from 'react'
import { Plus, FlaskConical, Pencil, Trash2, AlertTriangle } from 'lucide-react'
import { api, fmtTime } from '../lib/api'
import { LocalRecord } from '../lib/types'
import { Badge, EmptyState, ErrorBox, Loading, Modal, Field, Toggle, PageHeader } from '../components/ui'

export function LocalDNS() {
  const [items, setItems] = useState<LocalRecord[] | null>(null)
  const [err, setErr] = useState<unknown>(null)
  const [edit, setEdit] = useState<LocalRecord | 'new' | null>(null)
  const [testOpen, setTestOpen] = useState(false)
  const [warnings, setWarnings] = useState<string[]>([])

  const load = () => {
    api.get<LocalRecord[]>('/api/v1/local-dns').then(r => setItems(r ?? [])).catch(setErr)
  }
  useEffect(() => { load() }, [])

  const toggle = async (r: LocalRecord) => {
    await api.patch(`/api/v1/local-dns/${r.id}`, { enabled: !r.enabled }).then(load).catch(setErr)
  }
  const del = async (r: LocalRecord) => {
    if (!confirm(`Delete ${r.type} record for ${r.name}?`)) return
    await api.del(`/api/v1/local-dns/${r.id}`).then(load).catch(setErr)
  }

  if (!items) return err ? <ErrorBox error={err} /> : <Loading />

  return (
    <div className="space-y-4">
      <PageHeader title="Local DNS" desc="Records answered locally before forwarding — hostnames, rewrites, wildcards.">
        <div className="flex gap-2">
          <button className="btn-ghost" onClick={() => setTestOpen(true)}><FlaskConical className="h-3.5 w-3.5" /> Test lookup</button>
          <button className="btn-primary" onClick={() => { setWarnings([]); setEdit('new') }}><Plus className="h-3.5 w-3.5" /> Add record</button>
        </div>
      </PageHeader>
      <ErrorBox error={err} />
      {warnings.length > 0 && (
        <div className="rounded-md border border-amber-800/60 bg-amber-950/40 px-3 py-2 text-sm text-amber-300">
          {warnings.map((w, i) => <div key={i} className="flex items-center gap-2"><AlertTriangle className="h-3.5 w-3.5" /> {w}</div>)}
        </div>
      )}
      {items.length === 0 ? (
        <EmptyState title="No local DNS records"
          hint="Local records answer before forwarding — e.g. nas.home.lan → 192.168.1.10. Prefix a name with *. for wildcard." />
      ) : (
        <div className="card overflow-x-auto">
          <table className="w-full min-w-[720px]">
            <thead><tr>
              <th className="th">Name</th><th className="th">Type</th><th className="th">Value</th>
              <th className="th">TTL</th><th className="th">Comment</th><th className="th">On</th><th className="th" />
            </tr></thead>
            <tbody>
              {items.map(r => (
                <tr key={r.id} className="hover:bg-zinc-800/30">
                  <td className="td font-mono text-xs">{r.name}</td>
                  <td className="td"><Badge tone="accent">{r.type}</Badge></td>
                  <td className="td font-mono text-xs">{r.value}</td>
                  <td className="td text-xs text-zinc-500">{r.ttl}s</td>
                  <td className="td max-w-[160px] truncate text-xs text-zinc-500">{r.comment || '—'}</td>
                  <td className="td"><Toggle on={r.enabled} onChange={() => toggle(r)} /></td>
                  <td className="td">
                    <div className="flex justify-end gap-1">
                      <button className="btn-ghost px-2!" onClick={() => { setWarnings([]); setEdit(r) }}><Pencil className="h-3.5 w-3.5" /></button>
                      <button className="btn-subtle-danger px-2!" onClick={() => del(r)}><Trash2 className="h-3.5 w-3.5" /></button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {edit && <RecordModal rec={edit === 'new' ? null : edit}
        onClose={() => setEdit(null)}
        onSaved={w => { setWarnings(w); setEdit(null); load() }} />}
      {testOpen && <TestModal onClose={() => setTestOpen(false)} />}
    </div>
  )
}

function RecordModal({ rec, onClose, onSaved }: {
  rec: LocalRecord | null; onClose: () => void; onSaved: (warnings: string[]) => void
}) {
  const [name, setName] = useState(rec?.name || '')
  const [type, setType] = useState(rec?.type || 'A')
  const [value, setValue] = useState(rec?.value || '')
  const [ttl, setTtl] = useState(rec?.ttl || 300)
  const [comment, setComment] = useState(rec?.comment || '')
  const [err, setErr] = useState('')
  const save = async () => {
    try {
      const body = { name, type, value, ttl, comment }
      const res = rec
        ? await api.patch<{ record: LocalRecord; warnings: string[] }>(`/api/v1/local-dns/${rec.id}`, body)
        : await api.post<{ record: LocalRecord; warnings: string[] }>('/api/v1/local-dns', body)
      onSaved(res.warnings ?? [])
    } catch (e) { setErr(e instanceof Error ? e.message : String(e)) }
  }
  const placeholders: Record<string, string> = {
    A: '192.168.1.10', AAAA: 'fd00::10', CNAME: 'target.local', TXT: 'any text', PTR: 'host.local',
  }
  return (
    <Modal title={rec ? 'Edit record' : 'Add record'} onClose={onClose}>
      <div className="space-y-3">
        <Field label="Name" hint={'Owner name. "*.lan" is a wildcard; "1.1.168.192.in-addr.arpa" answers PTR lookups.'}>
          <input className="input w-full font-mono" value={name} onChange={e => setName(e.target.value)} placeholder="nas.home.lan" />
        </Field>
        <div className="grid grid-cols-2 gap-3">
          <Field label="Type">
            <select className="input w-full" value={type} onChange={e => setType(e.target.value)}>
              {['A', 'AAAA', 'CNAME', 'TXT', 'PTR'].map(t => <option key={t}>{t}</option>)}
            </select>
          </Field>
          <Field label="TTL (seconds)">
            <input className="input w-full" type="number" min={1} value={ttl} onChange={e => setTtl(Number(e.target.value))} />
          </Field>
        </div>
        <Field label="Value">
          <input className="input w-full font-mono" value={value} onChange={e => setValue(e.target.value)} placeholder={placeholders[type] || ''} />
        </Field>
        <Field label="Comment"><input className="input w-full" value={comment} onChange={e => setComment(e.target.value)} /></Field>
        {err && <ErrorBox error={err} />}
        <div className="flex justify-end gap-2 pt-1">
          <button className="btn-ghost" onClick={onClose}>Cancel</button>
          <button className="btn-primary" disabled={!name || !value} onClick={save}>Save</button>
        </div>
      </div>
    </Modal>
  )
}

function TestModal({ onClose }: { onClose: () => void }) {
  const [name, setName] = useState('')
  const [qtype, setQtype] = useState('A')
  const [res, setRes] = useState<{ matched: boolean; rcode?: string; answers?: string[] } | null>(null)
  const [err, setErr] = useState('')
  const run = async () => {
    setErr('')
    try { setRes(await api.post('/api/v1/local-dns/test', { name, qtype })) }
    catch (e) { setErr(e instanceof Error ? e.message : String(e)) }
  }
  return (
    <Modal title="Test local DNS lookup" onClose={onClose}>
      <div className="space-y-3">
        <div className="grid grid-cols-3 gap-3">
          <div className="col-span-2">
            <Field label="Name"><input className="input w-full font-mono" value={name} onChange={e => setName(e.target.value)} placeholder="nas.home.lan" /></Field>
          </div>
          <Field label="Type">
            <select className="input w-full" value={qtype} onChange={e => setQtype(e.target.value)}>
              {['A', 'AAAA', 'CNAME', 'TXT', 'PTR'].map(t => <option key={t}>{t}</option>)}
            </select>
          </Field>
        </div>
        <button className="btn-primary" disabled={!name} onClick={run}>Test</button>
        {err && <ErrorBox error={err} />}
        {res && (
          <div className="rounded-md border border-zinc-800 bg-zinc-950/50 p-3 text-sm">
            {res.matched ? (
              <>
                <Badge tone="ok">matched</Badge> <span className="text-zinc-400">{res.rcode}</span>
                <div className="mt-2 space-y-1">
                  {(res.answers ?? []).map((a, i) => <div key={i} className="font-mono text-xs text-zinc-300">{a}</div>)}
                </div>
              </>
            ) : (
              <span className="text-zinc-500">No local record — would be forwarded upstream.</span>
            )}
          </div>
        )}
        <p className="text-xs text-zinc-600">Tested {fmtTime(new Date().toISOString())} — local answers use the same code path as the live DNS server.</p>
      </div>
    </Modal>
  )
}
