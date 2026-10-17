import { useEffect, useState } from 'react'
import { Pencil, RotateCcw, Trash2, Plus, Fingerprint } from 'lucide-react'
import { api, fmtNum, fmtTime, fmtTimeShort } from '../lib/api'
import { Client, QueryRow, PolicyGroup, Identity } from '../lib/types'
import { Badge, EmptyState, ErrorBox, Loading, Modal, Field, PageHeader } from '../components/ui'

const CLASSIFICATIONS = ['', 'computer', 'phone', 'tablet', 'tv', 'iot', 'server', 'router', 'other']

export function Clients() {
  const [items, setItems] = useState<Client[] | null>(null)
  const [err, setErr] = useState<unknown>(null)
  const [edit, setEdit] = useState<Client | null>(null)
  const [addOpen, setAddOpen] = useState(false)
  const [viewQueries, setViewQueries] = useState<Client | null>(null)

  const [groups, setGroups] = useState<PolicyGroup[]>([])
  const [identOpen, setIdentOpen] = useState<Client | null>(null)

  const load = () => api.get<Client[]>('/api/v1/clients').then(r => setItems(r ?? [])).catch(setErr)
  useEffect(() => {
    load()
    api.get<PolicyGroup[]>('/api/v1/policies/groups').then(r => setGroups(r ?? [])).catch(() => {})
  }, [])

  const del = async (c: Client) => {
    if (!confirm(`Forget client ${c.alias || c.ip}? Its statistics will be removed.`)) return
    await api.del(`/api/v1/clients/${c.id}`).then(load).catch(setErr)
  }
  const reset = async (c: Client) => {
    if (!confirm(`Reset statistics for ${c.alias || c.ip}?`)) return
    await api.post(`/api/v1/clients/${c.id}/reset-stats?confirm=true`).then(load).catch(setErr)
  }

  if (!items) return err ? <ErrorBox error={err} /> : <Loading />
  return (
    <div className="space-y-4">
      <PageHeader title="Clients" desc="Devices that query Blacknet — assign aliases, groups and classifications.">
        <button className="btn-primary" onClick={() => setAddOpen(true)}><Plus className="h-3.5 w-3.5" /> Add client</button>
      </PageHeader>
      <ErrorBox error={err} />
      {items.length === 0 ? (
        <EmptyState title="No clients seen yet" hint="Devices appear here once they query Blacknet. Assign aliases to recognize them." />
      ) : (
        <div className="card overflow-x-auto">
          <table className="w-full min-w-[720px]">
            <thead><tr>
              <th className="th">Device</th><th className="th">IP</th><th className="th">Policy group</th>
              <th className="th">Type</th>
              <th className="th">First seen</th><th className="th">Last seen</th>
              <th className="th text-right">Queries</th><th className="th text-right">Blocked</th>
              <th className="th text-right">Block %</th><th className="th" />
            </tr></thead>
            <tbody>
              {items.map(c => (
                <tr key={c.id} className="hover:bg-zinc-800/30">
                  <td className="td font-medium text-zinc-200">{c.alias || <span className="text-zinc-600">unnamed</span>}</td>
                  <td className="td font-mono text-xs">{c.ip}</td>
                  <td className="td">
                    {c.policy_group ? <Badge tone="accent">{c.policy_group}</Badge> : <span className="text-zinc-700">default</span>}
                  </td>
                  <td className="td text-xs text-zinc-500">{c.classification || '—'}</td>
                  <td className="td text-xs text-zinc-500">{fmtTime(c.first_seen)}</td>
                  <td className="td text-xs text-zinc-500">{fmtTime(c.last_seen)}</td>
                  <td className="td text-right tabular-nums">{fmtNum(c.total_queries)}</td>
                  <td className="td text-right tabular-nums">{fmtNum(c.blocked_queries)}</td>
                  <td className="td text-right tabular-nums">{c.block_pct.toFixed(1)}%</td>
                  <td className="td">
                    <div className="flex justify-end gap-1">
                      <button className="btn-ghost px-2!" title="Identities" onClick={() => setIdentOpen(c)}>
                        <Fingerprint className="h-3.5 w-3.5" />
                      </button>
                      <button className="btn-ghost px-2!" title="Recent queries" onClick={() => setViewQueries(c)}>
                        <ScrollIcon />
                      </button>
                      <button className="btn-ghost px-2!" title="Edit" onClick={() => setEdit(c)}><Pencil className="h-3.5 w-3.5" /></button>
                      <button className="btn-ghost px-2!" title="Reset stats" onClick={() => reset(c)}><RotateCcw className="h-3.5 w-3.5" /></button>
                      <button className="btn-subtle-danger px-2!" title="Delete" onClick={() => del(c)}><Trash2 className="h-3.5 w-3.5" /></button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {edit && <EditModal client={edit} groups={groups} onClose={() => setEdit(null)} onSaved={() => { setEdit(null); load() }} />}
      {addOpen && <AddModal groups={groups} onClose={() => setAddOpen(false)} onSaved={() => { setAddOpen(false); load() }} />}
      {viewQueries && <ClientQueries client={viewQueries} onClose={() => setViewQueries(null)} />}
      {identOpen && <IdentitiesModal client={identOpen} onClose={() => setIdentOpen(null)} />}
    </div>
  )
}

function ScrollIcon() {
  return <svg className="h-3.5 w-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75"><path d="M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01" /></svg>
}

function EditModal({ client, groups, onClose, onSaved }: {
  client: Client; groups: PolicyGroup[]; onClose: () => void; onSaved: () => void
}) {
  const [alias, setAlias] = useState(client.alias)
  const [group, setGroup] = useState(client.group)
  const [policyGroupId, setPolicyGroupId] = useState(client.policy_group_id)
  const [classification, setClassification] = useState(client.classification)
  const [notes, setNotes] = useState(client.notes)
  const [err, setErr] = useState('')
  const save = async () => {
    try {
      await api.patch(`/api/v1/clients/${client.id}`,
        { alias, group, policy_group_id: policyGroupId, classification, notes })
      onSaved()
    }
    catch (e) { setErr(e instanceof Error ? e.message : String(e)) }
  }
  return (
    <Modal title={`Edit ${client.ip}`} onClose={onClose}>
      <div className="space-y-3">
        <Field label="Alias"><input className="input w-full" value={alias} onChange={e => setAlias(e.target.value)} placeholder="Emre's Laptop" /></Field>
        <div className="grid grid-cols-2 gap-3">
          <Field label="Policy group" hint="Filtering policy; overrides the legacy label below.">
            <select className="input w-full" value={policyGroupId} onChange={e => setPolicyGroupId(Number(e.target.value))}>
              <option value={0}>Default</option>
              {groups.map(g => <option key={g.id} value={g.id}>{g.name}</option>)}
            </select>
          </Field>
          <Field label="Device type">
            <select className="input w-full" value={classification} onChange={e => setClassification(e.target.value)}>
              {CLASSIFICATIONS.map(c => <option key={c} value={c}>{c || 'unclassified'}</option>)}
            </select>
          </Field>
        </div>
        <Field label="Legacy label"><input className="input w-full" value={group} onChange={e => setGroup(e.target.value)} placeholder="e.g. family, iot" /></Field>
        <Field label="Notes"><input className="input w-full" value={notes} onChange={e => setNotes(e.target.value)} /></Field>
        {client.identity_source && <p className="text-xs text-zinc-600">identity source: {client.identity_source}</p>}
        {err && <ErrorBox error={err} />}
        <div className="flex justify-end gap-2 pt-1">
          <button className="btn-ghost" onClick={onClose}>Cancel</button>
          <button className="btn-primary" onClick={save}>Save</button>
        </div>
      </div>
    </Modal>
  )
}

function AddModal({ groups, onClose, onSaved }: { groups: PolicyGroup[]; onClose: () => void; onSaved: () => void }) {
  const [ip, setIp] = useState(''); const [alias, setAlias] = useState(''); const [group, setGroup] = useState('')
  const [policyGroupId, setPolicyGroupId] = useState(0)
  const [err, setErr] = useState('')
  const save = async () => {
    try { await api.post('/api/v1/clients', { ip, alias, group, policy_group_id: policyGroupId }); onSaved() }
    catch (e) { setErr(e instanceof Error ? e.message : String(e)) }
  }
  return (
    <Modal title="Add client" onClose={onClose}>
      <div className="space-y-3">
        <Field label="IP address"><input className="input w-full font-mono" value={ip} onChange={e => setIp(e.target.value)} placeholder="192.168.1.50" /></Field>
        <Field label="Alias"><input className="input w-full" value={alias} onChange={e => setAlias(e.target.value)} /></Field>
        <Field label="Policy group">
          <select className="input w-full" value={policyGroupId} onChange={e => setPolicyGroupId(Number(e.target.value))}>
            <option value={0}>Default</option>
            {groups.map(g => <option key={g.id} value={g.id}>{g.name}</option>)}
          </select>
        </Field>
        <Field label="Legacy label"><input className="input w-full" value={group} onChange={e => setGroup(e.target.value)} /></Field>
        {err && <ErrorBox error={err} />}
        <div className="flex justify-end gap-2 pt-1">
          <button className="btn-ghost" onClick={onClose}>Cancel</button>
          <button className="btn-primary" disabled={!ip} onClick={save}>Add</button>
        </div>
      </div>
    </Modal>
  )
}

function IdentitiesModal({ client, onClose }: { client: Client; onClose: () => void }) {
  const [items, setItems] = useState<Identity[] | null>(null)
  const [kind, setKind] = useState<'ip' | 'mac' | 'cidr' | 'hostname'>('ip')
  const [value, setValue] = useState('')
  const [err, setErr] = useState('')
  const load = () => api.get<Identity[]>(`/api/v1/clients/${client.id}/identities`)
    .then(r => setItems(r ?? [])).catch(e => { setErr(e instanceof Error ? e.message : String(e)); setItems([]) })
  useEffect(() => { load() }, [client.id])
  const bind = async () => {
    try { await api.post(`/api/v1/clients/${client.id}/identities`, { kind, value }); setValue(''); load() }
    catch (e) { setErr(e instanceof Error ? e.message : String(e)) }
  }
  const unbind = async (i: Identity) => {
    await api.del(`/api/v1/clients/${client.id}/identities/${i.id}`).then(load).catch(e => setErr(String(e)))
  }
  return (
    <Modal title={`Identities — ${client.alias || client.ip}`} onClose={onClose}>
      <div className="space-y-3">
        <p className="text-xs text-zinc-500">
          Alternate identities (MAC, hostname, CIDR) keep this device in its policy group even when its IP changes.
        </p>
        {!items ? <Loading /> : items.length === 0 ? (
          <div className="py-4 text-center text-xs text-zinc-600">No extra identities bound.</div>
        ) : (
          <table className="w-full">
            <thead><tr><th className="th">Kind</th><th className="th">Value</th><th className="th" /></tr></thead>
            <tbody>
              {items.map(i => (
                <tr key={i.id}>
                  <td className="td"><Badge tone="accent">{i.kind}</Badge></td>
                  <td className="td font-mono text-xs">{i.value}</td>
                  <td className="td text-right tabular-nums"><button className="btn-subtle-danger px-2!" onClick={() => unbind(i)}><Trash2 className="h-3.5 w-3.5" /></button></td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        <div className="flex items-end gap-2 border-t border-zinc-800 pt-3">
          <Field label="Kind">
            <select className="input" value={kind} onChange={e => setKind(e.target.value as any)}>
              <option value="ip">IP</option><option value="mac">MAC</option>
              <option value="cidr">CIDR</option><option value="hostname">Hostname</option>
            </select>
          </Field>
          <div className="flex-1">
            <Field label="Value"><input className="input w-full font-mono" value={value} onChange={e => setValue(e.target.value)} /></Field>
          </div>
          <button className="btn-primary" disabled={!value} onClick={bind}>Bind</button>
        </div>
        {err && <ErrorBox error={err} />}
      </div>
    </Modal>
  )
}

function ClientQueries({ client, onClose }: { client: Client; onClose: () => void }) {
  const [rows, setRows] = useState<QueryRow[] | null>(null)
  useEffect(() => {
    api.get<{ items: QueryRow[] }>(`/api/v1/clients/${client.id}/queries?per_page=50`)
      .then(r => setRows(r.items ?? [])).catch(() => setRows([]))
  }, [client.id])
  return (
    <Modal title={`Recent queries — ${client.alias || client.ip}`} onClose={onClose} wide>
      {!rows ? <Loading /> : rows.length === 0 ? (
        <div className="py-6 text-center text-xs text-zinc-600">No queries recorded</div>
      ) : (
        <table className="w-full">
          <thead><tr><th className="th">Time</th><th className="th">Domain</th><th className="th">Type</th><th className="th">Decision</th></tr></thead>
          <tbody>
            {rows.map(q => (
              <tr key={q.id}>
                <td className="td text-xs text-zinc-500 whitespace-nowrap">{fmtTime(q.time)}</td>
                <td className="td font-mono text-xs max-w-[300px] truncate">{q.domain}</td>
                <td className="td text-xs text-zinc-500">{q.qtype_name || q.qtype}</td>
                <td className="td">{q.blocked ? <Badge tone="bad">blocked</Badge> : <Badge tone="muted">allowed</Badge>}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </Modal>
  )
}
