import { useEffect, useState } from 'react'
import { Plus, FlaskConical, Pencil, Trash2, Copy, Link2 } from 'lucide-react'
import { api, fmtTime } from '../lib/api'
import { PolicyGroup, Assignment, Client, Upstream, Explanation } from '../lib/types'
import { Badge, EmptyState, ErrorBox, Loading, Modal, Field, Toggle, PageHeader } from '../components/ui'

export function Policies() {
  const [groups, setGroups] = useState<PolicyGroup[] | null>(null)
  const [assignments, setAssignments] = useState<Assignment[]>([])
  const [clients, setClients] = useState<Client[]>([])
  const [upstreams, setUpstreams] = useState<Upstream[]>([])
  const [err, setErr] = useState<unknown>(null)
  const [editGroup, setEditGroup] = useState<PolicyGroup | 'new' | null>(null)
  const [assignOpen, setAssignOpen] = useState(false)
  const [simOpen, setSimOpen] = useState(false)

  const load = () => {
    api.get<PolicyGroup[]>('/api/v1/policies/groups').then(r => setGroups(r ?? [])).catch(setErr)
    api.get<Assignment[]>('/api/v1/policies/assignments').then(r => setAssignments(r ?? [])).catch(() => {})
    api.get<Client[]>('/api/v1/clients').then(r => setClients(r ?? [])).catch(() => {})
    api.get<Upstream[]>('/api/v1/upstreams').then(r => setUpstreams(r ?? [])).catch(() => {})
  }
  useEffect(() => { load() }, [])

  const toggleGroup = async (g: PolicyGroup) => {
    await api.patch(`/api/v1/policies/groups/${g.id}`, { enabled: !g.enabled }).then(load).catch(setErr)
  }
  const delGroup = async (g: PolicyGroup) => {
    if (!confirm(`Delete group "${g.name}"? Its assignments and group-scoped rules are removed.`)) return
    await api.del(`/api/v1/policies/groups/${g.id}?confirm=true`).then(load).catch(setErr)
  }
  const dupGroup = async (g: PolicyGroup) => {
    await api.post(`/api/v1/policies/groups/${g.id}/duplicate`).then(load).catch(setErr)
  }
  const delAssignment = async (a: Assignment) => {
    await api.del(`/api/v1/policies/assignments/${a.id}`).then(load).catch(setErr)
  }

  if (!groups) return err ? <ErrorBox error={err} /> : <Loading />
  const upstreamName = (id: number) => id === 0 ? 'default pool' : (upstreams.find(u => u.id === id)?.name || `#${id}`)

  return (
    <div className="space-y-4">
      <PageHeader title="Policy Groups" desc="Apply different filtering rules, lists and upstreams to groups of devices.">
        <div className="flex gap-2">
          <button className="btn-ghost" onClick={() => setSimOpen(true)}><FlaskConical className="h-3.5 w-3.5" /> Simulate</button>
          <button className="btn-ghost" onClick={() => setAssignOpen(true)}><Link2 className="h-3.5 w-3.5" /> Add assignment</button>
          <button className="btn-primary" onClick={() => setEditGroup('new')}><Plus className="h-3.5 w-3.5" /> Add group</button>
        </div>
      </PageHeader>
      <ErrorBox error={err} />

      {groups.length === 0 ? (
        <EmptyState title="No policy groups"
          hint="Groups let different devices get different filtering — e.g. stricter lists for kids, a permissive group for servers." />
      ) : (
        <div className="grid gap-3 sm:grid-cols-2">
          {groups.map(g => (
            <div key={g.id} className="card p-4">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <span className="font-medium text-zinc-100">{g.name}</span>
                  {!g.enabled && <Badge tone="muted">disabled</Badge>}
                </div>
                <div className="flex items-center gap-2">
                  <Toggle on={g.enabled} onChange={() => toggleGroup(g)} />
                  <button className="btn-ghost px-2!" title="Duplicate" onClick={() => dupGroup(g)}><Copy className="h-3.5 w-3.5" /></button>
                  <button className="btn-ghost px-2!" onClick={() => setEditGroup(g)}><Pencil className="h-3.5 w-3.5" /></button>
                  <button className="btn-subtle-danger px-2!" onClick={() => delGroup(g)}><Trash2 className="h-3.5 w-3.5" /></button>
                </div>
              </div>
              {g.description && <div className="mt-1 text-xs text-zinc-500">{g.description}</div>}
              <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-xs text-zinc-500">
                <span>{g.client_count ?? 0} client{g.client_count === 1 ? '' : 's'}</span>
                <span>upstream: {upstreamName(g.upstream_id)}</span>
                <span>{(g.list_ids ?? []).length} group list{(g.list_ids ?? []).length === 1 ? '' : 's'}</span>
              </div>
            </div>
          ))}
        </div>
      )}

      <h2 className="pt-2 text-sm font-semibold text-zinc-200">Assignments</h2>
      <p className="text-xs text-zinc-500">
        Assignments map devices into groups. CIDR and exact-IP matches win over client records; the most specific CIDR wins.
      </p>
      {assignments.length === 0 ? (
        <EmptyState title="No assignments" hint="Devices with no assignment use the default policy." />
      ) : (
        <div className="card overflow-x-auto">
          <table className="w-full min-w-[560px]">
            <thead><tr>
              <th className="th">Kind</th><th className="th">Value</th><th className="th">Group</th><th className="th">Added</th><th className="th" />
            </tr></thead>
            <tbody>
              {assignments.map(a => (
                <tr key={a.id} className="hover:bg-zinc-800/30">
                  <td className="td"><Badge tone="accent">{a.kind}</Badge></td>
                  <td className="td font-mono text-xs">{a.value}</td>
                  <td className="td text-xs">{a.group_name || `#${a.group_id}`}</td>
                  <td className="td text-xs text-zinc-500">{fmtTime(a.created_at)}</td>
                  <td className="td text-right">
                    <button className="btn-subtle-danger px-2!" onClick={() => delAssignment(a)}><Trash2 className="h-3.5 w-3.5" /></button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {editGroup && <GroupModal group={editGroup === 'new' ? null : editGroup} upstreams={upstreams}
        onClose={() => setEditGroup(null)} onSaved={() => { setEditGroup(null); load() }} />}
      {assignOpen && <AssignModal groups={groups} clients={clients}
        onClose={() => setAssignOpen(false)} onSaved={() => { setAssignOpen(false); load() }} />}
      {simOpen && <SimModal groups={groups} clients={clients} onClose={() => setSimOpen(false)} />}
    </div>
  )
}

function GroupModal({ group, upstreams, onClose, onSaved }: {
  group: PolicyGroup | null; upstreams: Upstream[]; onClose: () => void; onSaved: () => void
}) {
  const [name, setName] = useState(group?.name || '')
  const [description, setDescription] = useState(group?.description || '')
  const [upstreamId, setUpstreamId] = useState(group?.upstream_id || 0)
  const [err, setErr] = useState('')
  const save = async () => {
    try {
      const body = { name, description, upstream_id: upstreamId }
      if (group) await api.patch(`/api/v1/policies/groups/${group.id}`, body)
      else await api.post('/api/v1/policies/groups', body)
      onSaved()
    } catch (e) { setErr(e instanceof Error ? e.message : String(e)) }
  }
  return (
    <Modal title={group ? 'Edit group' : 'Add group'} onClose={onClose}>
      <div className="space-y-3">
        <Field label="Name"><input className="input w-full" value={name} onChange={e => setName(e.target.value)} placeholder="Kids" /></Field>
        <Field label="Description"><input className="input w-full" value={description} onChange={e => setDescription(e.target.value)} /></Field>
        <Field label="Upstream resolver" hint="Override the default upstream pool for clients in this group.">
          <select className="input w-full" value={upstreamId} onChange={e => setUpstreamId(Number(e.target.value))}>
            <option value={0}>Default pool</option>
            {upstreams.map(u => <option key={u.id} value={u.id}>{u.name} ({u.address})</option>)}
          </select>
        </Field>
        {err && <ErrorBox error={err} />}
        <div className="flex justify-end gap-2 pt-1">
          <button className="btn-ghost" onClick={onClose}>Cancel</button>
          <button className="btn-primary" disabled={!name} onClick={save}>Save</button>
        </div>
      </div>
    </Modal>
  )
}

function AssignModal({ groups, clients, onClose, onSaved }: {
  groups: PolicyGroup[]; clients: Client[]; onClose: () => void; onSaved: () => void
}) {
  const [kind, setKind] = useState<'client' | 'ip' | 'cidr'>('client')
  const [value, setValue] = useState('')
  const [groupId, setGroupId] = useState(groups[0]?.id || 0)
  const [err, setErr] = useState('')
  const save = async () => {
    try {
      await api.post('/api/v1/policies/assignments', { kind, value, group_id: groupId })
      onSaved()
    } catch (e) { setErr(e instanceof Error ? e.message : String(e)) }
  }
  return (
    <Modal title="Add assignment" onClose={onClose}>
      <div className="space-y-3">
        <Field label="Kind">
          <select className="input w-full" value={kind} onChange={e => { setKind(e.target.value as any); setValue('') }}>
            <option value="client">Known client</option>
            <option value="ip">IP address</option>
            <option value="cidr">CIDR range</option>
          </select>
        </Field>
        {kind === 'client' ? (
          <Field label="Client">
            <select className="input w-full" value={value} onChange={e => setValue(e.target.value)}>
              <option value="">Choose…</option>
              {clients.map(c => <option key={c.id} value={String(c.id)}>{c.alias || c.ip}</option>)}
            </select>
          </Field>
        ) : (
          <Field label={kind === 'ip' ? 'IP address' : 'CIDR'}>
            <input className="input w-full font-mono" value={value} onChange={e => setValue(e.target.value)}
              placeholder={kind === 'ip' ? '192.168.1.50' : '192.168.1.0/24'} />
          </Field>
        )}
        <Field label="Group">
          <select className="input w-full" value={groupId} onChange={e => setGroupId(Number(e.target.value))}>
            {groups.map(g => <option key={g.id} value={g.id}>{g.name}</option>)}
          </select>
        </Field>
        {err && <ErrorBox error={err} />}
        <div className="flex justify-end gap-2 pt-1">
          <button className="btn-ghost" onClick={onClose}>Cancel</button>
          <button className="btn-primary" disabled={!value || !groupId} onClick={save}>Save</button>
        </div>
      </div>
    </Modal>
  )
}

function SimModal({ groups, clients, onClose }: { groups: PolicyGroup[]; clients: Client[]; onClose: () => void }) {
  const [domain, setDomain] = useState('')
  const [mode, setMode] = useState<'ip' | 'subject'>('ip')
  const [ip, setIp] = useState('')
  const [clientId, setClientId] = useState(0)
  const [groupId, setGroupId] = useState(0)
  const [at, setAt] = useState('')
  const [res, setRes] = useState<Explanation | null>(null)
  const [err, setErr] = useState('')
  const run = async () => {
    setErr('')
    try {
      const body: any = { domain }
      if (mode === 'ip') body.client_ip = ip
      else { body.client_id = clientId; if (groupId) body.group_id = groupId }
      if (at) body.at = new Date(at).toISOString()
      setRes(await api.post<Explanation>('/api/v1/policies/simulate', body))
    } catch (e) { setErr(e instanceof Error ? e.message : String(e)) }
  }
  return (
    <Modal title="Simulate a DNS decision" onClose={onClose} wide>
      <div className="space-y-3">
        <Field label="Domain"><input className="input w-full font-mono" value={domain} onChange={e => setDomain(e.target.value)} placeholder="ads.example.com" /></Field>
        <div className="grid grid-cols-2 gap-3">
          <Field label="Subject">
            <select className="input w-full" value={mode} onChange={e => setMode(e.target.value as any)}>
              <option value="ip">By source IP (uses real resolver)</option>
              <option value="subject">Hypothetical client/group</option>
            </select>
          </Field>
          <Field label="At time" hint="Optional — evaluate schedules at another time.">
            <input className="input w-full" type="datetime-local" value={at} onChange={e => setAt(e.target.value)} />
          </Field>
        </div>
        {mode === 'ip' ? (
          <Field label="Source IP"><input className="input w-full font-mono" value={ip} onChange={e => setIp(e.target.value)} placeholder="192.168.1.50" /></Field>
        ) : (
          <div className="grid grid-cols-2 gap-3">
            <Field label="Client">
              <select className="input w-full" value={clientId} onChange={e => setClientId(Number(e.target.value))}>
                <option value={0}>Any</option>
                {clients.map(c => <option key={c.id} value={c.id}>{c.alias || c.ip}</option>)}
              </select>
            </Field>
            <Field label="Group">
              <select className="input w-full" value={groupId} onChange={e => setGroupId(Number(e.target.value))}>
                <option value={0}>None (default)</option>
                {groups.map(g => <option key={g.id} value={g.id}>{g.name}</option>)}
              </select>
            </Field>
          </div>
        )}
        <button className="btn-primary" disabled={!domain || (mode === 'ip' && !ip)} onClick={run}>Run</button>
        {err && <ErrorBox error={err} />}
        {res && <ExplanationView ex={res} />}
      </div>
    </Modal>
  )
}

export function ExplanationView({ ex }: { ex: Explanation }) {
  return (
    <div className="rounded-md border border-zinc-800 bg-zinc-950/50 p-3 text-sm">
      <div className="flex flex-wrap items-center gap-2">
        {ex.decision.blocked ? <Badge tone="bad">blocked</Badge> : <Badge tone="ok">allowed</Badge>}
        <span className="text-zinc-400">{ex.decision.reason}</span>
        {ex.protection_off && <Badge tone="warn">protection off</Badge>}
        {ex.subject.group_id !== 0 && <Badge tone="accent">group #{ex.subject.group_id}</Badge>}
      </div>
      {(ex.active_schedules ?? []).length > 0 && (
        <div className="mt-2 text-xs text-zinc-500">active schedules: {ex.active_schedules!.join(', ')}</div>
      )}
      <ol className="mt-2 space-y-1 border-l-2 border-zinc-800 pl-3">
        {(ex.steps ?? []).map((s, i) => (
          <li key={i} className="text-xs">
            <span className={s.matched ? 'text-amber-300' : 'text-zinc-600'}>{s.matched ? '●' : '○'}</span>{' '}
            <span className="font-medium text-zinc-400">{s.stage}</span>
            <span className="text-zinc-600"> — {s.detail}</span>
            {s.rule && <span className="font-mono text-zinc-500"> (rule #{s.rule.id}: {s.rule.action} {s.rule.domain})</span>}
            {s.list_id ? <span className="font-mono text-zinc-500"> (list #{s.list_id})</span> : null}
          </li>
        ))}
      </ol>
    </div>
  )
}
