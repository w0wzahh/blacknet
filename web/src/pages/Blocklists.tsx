import { useEffect, useState } from 'react'
import { Plus, RefreshCw, Trash2 } from 'lucide-react'
import { api, fmtNum, fmtTime, fmtTimeShort } from '../lib/api'
import { Blocklist } from '../lib/types'
import { Badge, EmptyState, ErrorBox, Loading, Modal, Field, Toggle } from '../components/ui'

export function Blocklists() {
  const [items, setItems] = useState<Blocklist[] | null>(null)
  const [err, setErr] = useState<unknown>(null)
  const [addOpen, setAddOpen] = useState(false)
  const [refreshing, setRefreshing] = useState<number | null>(null)
  const [notice, setNotice] = useState('')

  const load = () => api.get<Blocklist[]>('/api/v1/blocklists').then(r => setItems(r ?? [])).catch(setErr)
  useEffect(() => { load() }, [])

  const toggle = async (b: Blocklist) => {
    await api.patch(`/api/v1/blocklists/${b.id}`, { enabled: !b.enabled }).then(load).catch(setErr)
  }
  const refresh = async (b: Blocklist) => {
    setRefreshing(b.id); setNotice('')
    try {
      const res = await api.post<{ message: string }>(`/api/v1/blocklists/${b.id}/refresh`)
      setNotice(`${b.name}: ${res.message}`)
      await load()
    } catch (e) { setErr(e) }
    setRefreshing(null)
  }
  const del = async (b: Blocklist) => {
    if (!confirm(`Delete "${b.name}"? Its ${fmtNum(b.rule_count)} imported domains will stop filtering.`)) return
    await api.del(`/api/v1/blocklists/${b.id}`).then(load).catch(setErr)
  }

  if (!items) return err ? <ErrorBox error={err} /> : <Loading />
  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-lg font-semibold text-zinc-100">Blocklists</h1>
        <button className="btn-primary" onClick={() => setAddOpen(true)}><Plus className="h-3.5 w-3.5" /> Add list</button>
      </div>
      <ErrorBox error={err} />
      {notice && <div className="rounded-md border border-emerald-800/60 bg-emerald-950/40 px-3 py-2 text-sm text-emerald-300">{notice}</div>}
      {items.length === 0 ? (
        <EmptyState title="No blocklists" hint="Add a blocklist URL to start importing domains." />
      ) : (
        <div className="card overflow-x-auto">
          <table className="w-full min-w-[760px]">
            <thead><tr>
              <th className="th">Name</th><th className="th">Source</th><th className="th">Status</th>
              <th className="th">Last refresh</th><th className="th text-right">Rules</th>
              <th className="th">Error</th><th className="th" />
            </tr></thead>
            <tbody>
              {items.map(b => (
                <tr key={b.id} className="hover:bg-zinc-800/30">
                  <td className="td font-medium text-zinc-200">{b.name}</td>
                  <td className="td max-w-[240px] truncate font-mono text-xs text-zinc-500" title={b.url}>{b.url}</td>
                  <td className="td">
                    <Toggle on={b.enabled} onChange={() => toggle(b)} />
                  </td>
                  <td className="td text-xs text-zinc-500 whitespace-nowrap">{b.last_refresh ? fmtTime(b.last_refresh) : 'never'}</td>
                  <td className="td text-right">{fmtNum(b.rule_count)}</td>
                  <td className="td max-w-[160px] truncate text-xs text-red-400" title={b.last_error}>{b.last_error || '—'}</td>
                  <td className="td">
                    <div className="flex justify-end gap-1">
                      <button className="btn-ghost px-2!" disabled={refreshing === b.id} onClick={() => refresh(b)} title="Refresh now">
                        <RefreshCw className={`h-3.5 w-3.5 ${refreshing === b.id ? 'animate-spin' : ''}`} />
                      </button>
                      <button className="btn-subtle-danger px-2!" onClick={() => del(b)} title="Delete"><Trash2 className="h-3.5 w-3.5" /></button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {addOpen && <AddModal onClose={() => setAddOpen(false)} onSaved={() => { setAddOpen(false); load() }} />}
    </div>
  )
}

function AddModal({ onClose, onSaved }: { onClose: () => void; onSaved: () => void }) {
  const [name, setName] = useState('')
  const [url, setUrl] = useState('')
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)
  const save = async () => {
    setBusy(true); setErr('')
    try { await api.post('/api/v1/blocklists', { name, url }); onSaved() }
    catch (e) { setErr(e instanceof Error ? e.message : String(e)); setBusy(false) }
  }
  return (
    <Modal title="Add blocklist" onClose={onClose}>
      <div className="space-y-3">
        <Field label="Name"><input className="input w-full" value={name} onChange={e => setName(e.target.value)} placeholder="My blocklist" /></Field>
        <Field label="Source URL" hint="https:// URLs only. The list downloads in the background after saving.">
          <input className="input w-full font-mono" value={url} onChange={e => setUrl(e.target.value)} placeholder="https://example.org/hosts.txt" />
        </Field>
        {err && <ErrorBox error={err} />}
        <div className="flex justify-end gap-2 pt-1">
          <button className="btn-ghost" onClick={onClose}>Cancel</button>
          <button className="btn-primary" disabled={busy || !name || !url} onClick={save}>{busy ? 'Adding…' : 'Add'}</button>
        </div>
      </div>
    </Modal>
  )
}
