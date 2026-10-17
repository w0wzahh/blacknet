import { useEffect, useState } from 'react'
import { Plus, Activity, Trash2, Pencil } from 'lucide-react'
import { api } from '../lib/api'
import { Upstream } from '../lib/types'
import { Badge, EmptyState, ErrorBox, Loading, Modal, Field, Toggle } from '../components/ui'

const PROTOCOLS = [
  { v: 'udp', label: 'DNS (UDP)', hint: 'host:53' },
  { v: 'tcp', label: 'DNS (TCP)', hint: 'host:53' },
  { v: 'dot', label: 'DNS-over-TLS', hint: 'host:853' },
  { v: 'doh', label: 'DNS-over-HTTPS', hint: 'https://host/dns-query' },
]

const EXAMPLES = [
  { name: 'Cloudflare', protocol: 'udp', address: '1.1.1.1:53' },
  { name: 'Cloudflare DoT', protocol: 'dot', address: '1.1.1.1:853' },
  { name: 'Cloudflare DoH', protocol: 'doh', address: 'https://cloudflare-dns.com/dns-query' },
  { name: 'Quad9', protocol: 'udp', address: '9.9.9.9:53' },
  { name: 'Quad9 DoT', protocol: 'dot', address: '9.9.9.9:853' },
  { name: 'Quad9 DoH', protocol: 'doh', address: 'https://dns.quad9.net/dns-query' },
  { name: 'Google', protocol: 'udp', address: '8.8.8.8:53' },
  { name: 'Google DoH', protocol: 'doh', address: 'https://dns.google/dns-query' },
]

export function Upstreams() {
  const [items, setItems] = useState<Upstream[] | null>(null)
  const [err, setErr] = useState<unknown>(null)
  const [edit, setEdit] = useState<Upstream | 'new' | null>(null)
  const [testing, setTesting] = useState<Record<number, boolean>>({})
  const [testAll, setTestAll] = useState(false)

  const load = () => api.get<Upstream[]>('/api/v1/upstreams').then(setItems).catch(setErr)
  useEffect(() => { load() }, [])

  const toggle = async (u: Upstream) =>
    api.patch(`/api/v1/upstreams/${u.id}`, { enabled: !u.enabled }).then(load).catch(setErr)
  const del = async (u: Upstream) => {
    if (!confirm(`Remove upstream ${u.name || u.address}?`)) return
    await api.del(`/api/v1/upstreams/${u.id}`).then(load).catch(setErr)
  }
  const test = async (u: Upstream) => {
    setTesting(t => ({ ...t, [u.id]: true }))
    try { await api.post('/api/v1/upstreams/test', { id: u.id }) ; await load() }
    catch (e) { setErr(e) }
    setTesting(t => ({ ...t, [u.id]: false }))
  }
  const testAllUpstreams = async () => {
    setTestAll(true)
    try { await api.post('/api/v1/upstreams/test', {}); await load() } catch (e) { setErr(e) }
    setTestAll(false)
  }

  if (!items) return <Loading />
  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-lg font-semibold text-zinc-100">Upstream DNS</h1>
        <div className="flex gap-2">
          <button className="btn-ghost" disabled={testAll} onClick={testAllUpstreams}>
            <Activity className="h-3.5 w-3.5" /> {testAll ? 'Testing…' : 'Test all'}
          </button>
          <button className="btn-primary" onClick={() => setEdit('new')}><Plus className="h-3.5 w-3.5" /> Add upstream</button>
        </div>
      </div>
      <ErrorBox error={err} />
      {items.length === 0 ? (
        <EmptyState title="No upstream resolvers" hint="Add at least one upstream so allowed queries can resolve." />
      ) : (
        <div className="card overflow-x-auto">
          <table className="w-full min-w-[760px]">
            <thead><tr>
              <th className="th">Name</th><th className="th">Protocol</th><th className="th">Address</th>
              <th className="th text-right">Priority</th><th className="th text-right">Timeout</th>
              <th className="th">Health</th><th className="th text-right">RTT</th>
              <th className="th">Enabled</th><th className="th" />
            </tr></thead>
            <tbody>
              {items.map(u => (
                <tr key={u.id} className="hover:bg-zinc-800/30">
                  <td className="td font-medium text-zinc-200">{u.name}</td>
                  <td className="td"><Badge tone="muted">{u.protocol.toUpperCase()}</Badge></td>
                  <td className="td font-mono text-xs max-w-[220px] truncate" title={u.address}>{u.address}</td>
                  <td className="td text-right text-zinc-500">{u.priority}</td>
                  <td className="td text-right text-zinc-500">{Math.round(u.timeout / 1e6)}ms</td>
                  <td className="td">
                    {u.stats?.healthy
                      ? <Badge tone="ok">healthy</Badge>
                      : <Badge tone={u.stats?.queries > 0 || u.stats?.last_error ? 'bad' : 'muted'}>
                          {u.stats?.last_error ? 'failing' : 'untested'}
                        </Badge>}
                    {u.stats?.last_error && <div className="mt-0.5 max-w-[160px] truncate text-xs text-red-500" title={u.stats.last_error}>{u.stats.last_error}</div>}
                  </td>
                  <td className="td text-right text-xs text-zinc-500">{u.stats?.last_rtt_ms ? u.stats.last_rtt_ms.toFixed(0) + 'ms' : '—'}</td>
                  <td className="td"><Toggle on={u.enabled} onChange={() => toggle(u)} /></td>
                  <td className="td">
                    <div className="flex justify-end gap-1">
                      <button className="btn-ghost !px-2" disabled={testing[u.id]} onClick={() => test(u)} title="Test now">
                        <Activity className="h-3.5 w-3.5" />
                      </button>
                      <button className="btn-ghost !px-2" onClick={() => setEdit(u)}><Pencil className="h-3.5 w-3.5" /></button>
                      <button className="btn-subtle-danger !px-2" onClick={() => del(u)}><Trash2 className="h-3.5 w-3.5" /></button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {edit && <UpstreamModal upstream={edit === 'new' ? null : edit} onClose={() => setEdit(null)} onSaved={() => { setEdit(null); load() }} />}
    </div>
  )
}

function UpstreamModal({ upstream, onClose, onSaved }: {
  upstream: Upstream | null; onClose: () => void; onSaved: () => void
}) {
  const [name, setName] = useState(upstream?.name || '')
  const [protocol, setProtocol] = useState(upstream?.protocol || 'udp')
  const [address, setAddress] = useState(upstream?.address || '')
  const [priority, setPriority] = useState(upstream?.priority ?? 0)
  const [timeoutMs, setTimeoutMs] = useState(upstream ? Math.round(upstream.timeout / 1e6) : 5000)
  const [err, setErr] = useState('')
  const save = async () => {
    try {
      const body = { name, protocol, address, priority, timeout_ms: timeoutMs }
      if (upstream) await api.patch(`/api/v1/upstreams/${upstream.id}`, body)
      else await api.post('/api/v1/upstreams', body)
      onSaved()
    } catch (e) { setErr(e instanceof Error ? e.message : String(e)) }
  }
  const hint = PROTOCOLS.find(p => p.v === protocol)?.hint
  return (
    <Modal title={upstream ? 'Edit upstream' : 'Add upstream'} onClose={onClose} wide>
      <div className="space-y-3">
        {!upstream && (
          <div className="flex flex-wrap gap-1.5">
            {EXAMPLES.map(ex => (
              <button key={ex.name} className="btn-ghost !px-2 !py-1 text-xs"
                onClick={() => { setName(ex.name); setProtocol(ex.protocol as any); setAddress(ex.address) }}>
                {ex.name}
              </button>
            ))}
          </div>
        )}
        <div className="grid grid-cols-2 gap-3">
          <Field label="Name"><input className="input w-full" value={name} onChange={e => setName(e.target.value)} placeholder="Cloudflare" /></Field>
          <Field label="Protocol">
            <select className="input w-full" value={protocol} onChange={e => setProtocol(e.target.value as any)}>
              {PROTOCOLS.map(p => <option key={p.v} value={p.v}>{p.label}</option>)}
            </select>
          </Field>
        </div>
        <Field label="Address" hint={hint}>
          <input className="input w-full font-mono" value={address} onChange={e => setAddress(e.target.value)} placeholder={hint} />
        </Field>
        <div className="grid grid-cols-2 gap-3">
          <Field label="Priority" hint="Lower values are tried first in sequential mode.">
            <input className="input w-full" type="number" value={priority} onChange={e => setPriority(Number(e.target.value))} />
          </Field>
          <Field label="Timeout (ms)">
            <input className="input w-full" type="number" value={timeoutMs} onChange={e => setTimeoutMs(Number(e.target.value))} />
          </Field>
        </div>
        {err && <ErrorBox error={err} />}
        <div className="flex justify-end gap-2 pt-1">
          <button className="btn-ghost" onClick={onClose}>Cancel</button>
          <button className="btn-primary" disabled={!address} onClick={save}>Save</button>
        </div>
      </div>
    </Modal>
  )
}
