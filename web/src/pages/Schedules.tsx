import { useEffect, useState } from 'react'
import { Plus, Pencil, Trash2, Eye } from 'lucide-react'
import { api, fmtTime } from '../lib/api'
import { Schedule, SchedulePreview, PolicyGroup, Client, Blocklist } from '../lib/types'
import { Badge, EmptyState, ErrorBox, Loading, Modal, Field, Toggle } from '../components/ui'

const DAYS = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat']

function fmtWindow(sc: Schedule): string {
  const days = DAYS.filter((_, i) => sc.days_mask & (1 << i)).join(' ') || '—'
  const hm = (m: number) => `${String(Math.floor(m / 60)).padStart(2, '0')}:${String(m % 60).padStart(2, '0')}`
  return `${days} ${hm(sc.start_min)}–${hm(sc.end_min)}`
}

export function Schedules() {
  const [items, setItems] = useState<Schedule[] | null>(null)
  const [groups, setGroups] = useState<PolicyGroup[]>([])
  const [clients, setClients] = useState<Client[]>([])
  const [lists, setLists] = useState<Blocklist[]>([])
  const [err, setErr] = useState<unknown>(null)
  const [edit, setEdit] = useState<Schedule | 'new' | null>(null)
  const [preview, setPreview] = useState<SchedulePreview | null>(null)

  const load = () => {
    api.get<Schedule[]>('/api/v1/schedules').then(r => setItems(r ?? [])).catch(setErr)
    api.get<PolicyGroup[]>('/api/v1/policies/groups').then(r => setGroups(r ?? [])).catch(() => {})
    api.get<Client[]>('/api/v1/clients').then(r => setClients(r ?? [])).catch(() => {})
    api.get<Blocklist[]>('/api/v1/blocklists').then(r => setLists(r ?? [])).catch(() => {})
  }
  useEffect(() => { load() }, [])

  const toggle = async (s: Schedule) => {
    await api.patch(`/api/v1/schedules/${s.id}`, { enabled: !s.enabled }).then(load).catch(setErr)
  }
  const del = async (s: Schedule) => {
    if (!confirm(`Delete schedule "${s.name}"?`)) return
    await api.del(`/api/v1/schedules/${s.id}`).then(load).catch(setErr)
  }
  const showPreview = async (s: Schedule) => {
    setPreview(await api.get<SchedulePreview>(`/api/v1/schedules/${s.id}/preview`))
  }

  if (!items) return err ? <ErrorBox error={err} /> : <Loading />

  const targetName = (s: Schedule) => {
    if (s.target_kind === 'all') return 'all clients'
    if (s.target_kind === 'group') return 'group: ' + (groups.find(g => g.id === s.target_id)?.name || `#${s.target_id}`)
    if (s.target_kind === 'client') return 'client: ' + (clients.find(c => c.id === s.target_id)?.alias || `#${s.target_id}`)
    return `${s.target_kind} #${s.target_id}`
  }
  const effectLabel = (s: Schedule) => ({
    protection_off: 'pause protection (allow all)',
    protection_on: 'force filtering on',
    extra_lists: `apply ${(s.list_ids ?? []).length} extra lists`,
  } as Record<string, string>)[s.effect] || s.effect

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-lg font-semibold text-zinc-100">Schedules</h1>
        <button className="btn-primary" onClick={() => setEdit('new')}><Plus className="h-3.5 w-3.5" /> Add schedule</button>
      </div>
      <ErrorBox error={err} />
      {items.length === 0 ? (
        <EmptyState title="No schedules"
          hint='Schedules change filtering by time — e.g. "bedtime" blocks everything for the Kids group after 21:00.' />
      ) : (
        <div className="card overflow-x-auto">
          <table className="w-full min-w-[760px]">
            <thead><tr>
              <th className="th">Name</th><th className="th">When</th><th className="th">Target</th>
              <th className="th">Effect</th><th className="th">On</th><th className="th" />
            </tr></thead>
            <tbody>
              {items.map(s => (
                <tr key={s.id} className="hover:bg-zinc-800/30">
                  <td className="td font-medium">{s.name}</td>
                  <td className="td font-mono text-xs text-zinc-400">{fmtWindow(s)} {s.tz !== 'UTC' && <span className="text-zinc-600">({s.tz})</span>}</td>
                  <td className="td text-xs">{targetName(s)}</td>
                  <td className="td text-xs text-zinc-400">{effectLabel(s)}</td>
                  <td className="td"><Toggle on={s.enabled} onChange={() => toggle(s)} /></td>
                  <td className="td">
                    <div className="flex justify-end gap-1">
                      <button className="btn-ghost px-2!" title="Preview" onClick={() => showPreview(s)}><Eye className="h-3.5 w-3.5" /></button>
                      <button className="btn-ghost px-2!" onClick={() => setEdit(s)}><Pencil className="h-3.5 w-3.5" /></button>
                      <button className="btn-subtle-danger px-2!" onClick={() => del(s)}><Trash2 className="h-3.5 w-3.5" /></button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {edit && <ScheduleModal sc={edit === 'new' ? null : edit} groups={groups} clients={clients} lists={lists}
        onClose={() => setEdit(null)} onSaved={() => { setEdit(null); load() }} />}
      {preview && (
        <Modal title={`Preview: ${preview.schedule.name}`} onClose={() => setPreview(null)}>
          <div className="space-y-2 text-sm">
            <div>Right now: {preview.active ? <Badge tone="warn">active</Badge> : <Badge tone="muted">inactive</Badge>}</div>
            <div className="text-xs text-zinc-500">Next transitions:</div>
            {(preview.transitions ?? []).length === 0 ? (
              <div className="text-xs text-zinc-600">None upcoming (check the day mask and date range).</div>
            ) : (preview.transitions ?? []).map((t, i) => (
              <div key={i} className="flex items-center gap-2 text-xs">
                <span className="font-mono text-zinc-400">{fmtTime(t.at)}</span>
                {t.to_active ? <Badge tone="warn">becomes active</Badge> : <Badge tone="muted">becomes inactive</Badge>}
              </div>
            ))}
          </div>
        </Modal>
      )}
    </div>
  )
}

function ScheduleModal({ sc, groups, clients, lists, onClose, onSaved }: {
  sc: Schedule | null; groups: PolicyGroup[]; clients: Client[]; lists: Blocklist[]
  onClose: () => void; onSaved: () => void
}) {
  const [name, setName] = useState(sc?.name || '')
  const [tz, setTz] = useState(sc?.tz || Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC')
  const [days, setDays] = useState(sc?.days_mask ?? 0b1111111)
  const [start, setStart] = useState(sc ? minToHMS(sc.start_min) : '21:00')
  const [end, setEnd] = useState(sc ? minToHMS(sc.end_min) : '07:00')
  const [targetKind, setTargetKind] = useState(sc?.target_kind || 'all')
  const [targetId, setTargetId] = useState(sc?.target_id || 0)
  const [effect, setEffect] = useState(sc?.effect || 'protection_off')
  const [listIds, setListIds] = useState<number[]>(sc?.list_ids ?? [])
  const [err, setErr] = useState('')

  const toMin = (h: string) => { const [hh, mm] = h.split(':').map(Number); return hh * 60 + mm }
  const save = async () => {
    try {
      const body: any = {
        name, tz, days_mask: days, start_min: toMin(start), end_min: toMin(end),
        target_kind: targetKind, target_id: targetId, effect,
      }
      if (effect === 'extra_lists') body.list_ids = listIds
      if (sc) await api.patch(`/api/v1/schedules/${sc.id}`, body)
      else await api.post('/api/v1/schedules', body)
      onSaved()
    } catch (e) { setErr(e instanceof Error ? e.message : String(e)) }
  }

  return (
    <Modal title={sc ? 'Edit schedule' : 'Add schedule'} onClose={onClose} wide>
      <div className="space-y-3">
        <Field label="Name"><input className="input w-full" value={name} onChange={e => setName(e.target.value)} placeholder="Bedtime" /></Field>
        <div>
          <span className="mb-1 block text-xs font-medium text-zinc-400">Days</span>
          <div className="flex gap-1">
            {DAYS.map((d, i) => (
              <button key={d} type="button"
                className={`rounded border px-2 py-1 text-xs cursor-pointer ${days & (1 << i) ? 'border-violet-700 bg-violet-950/50 text-violet-300' : 'border-zinc-700 text-zinc-500'}`}
                onClick={() => setDays(days ^ (1 << i))}>{d}</button>
            ))}
          </div>
        </div>
        <div className="grid grid-cols-3 gap-3">
          <Field label="From"><input className="input w-full font-mono" type="time" value={start} onChange={e => setStart(e.target.value)} /></Field>
          <Field label="Until" hint="May cross midnight."><input className="input w-full font-mono" type="time" value={end} onChange={e => setEnd(e.target.value)} /></Field>
          <Field label="Timezone"><input className="input w-full" value={tz} onChange={e => setTz(e.target.value)} /></Field>
        </div>
        <div className="grid grid-cols-2 gap-3">
          <Field label="Applies to">
            <select className="input w-full" value={targetKind} onChange={e => { setTargetKind(e.target.value); setTargetId(0) }}>
              <option value="all">All clients</option>
              <option value="group">A policy group</option>
              <option value="client">A single client</option>
            </select>
          </Field>
          {targetKind !== 'all' && (
            <Field label={targetKind === 'group' ? 'Group' : 'Client'}>
              <select className="input w-full" value={targetId} onChange={e => setTargetId(Number(e.target.value))}>
                <option value={0}>Choose…</option>
                {(targetKind === 'group' ? groups : clients).map((x: any) =>
                  <option key={x.id} value={x.id}>{x.name || x.alias || x.ip}</option>)}
              </select>
            </Field>
          )}
          <Field label="Effect while active">
            <select className="input w-full" value={effect} onChange={e => setEffect(e.target.value)}>
              <option value="protection_off">Pause protection (allow all)</option>
              <option value="protection_on">Force filtering on</option>
              <option value="extra_lists">Apply extra blocklists</option>
            </select>
          </Field>
        </div>
        {effect === 'extra_lists' && (
          <Field label="Extra lists">
            <div className="max-h-32 space-y-1 overflow-y-auto rounded border border-zinc-800 p-2">
              {lists.map(l => (
                <label key={l.id} className="flex items-center gap-2 text-xs text-zinc-300">
                  <input type="checkbox" checked={listIds.includes(l.id)}
                    onChange={e => setListIds(e.target.checked ? [...listIds, l.id] : listIds.filter(x => x !== l.id))} />
                  {l.name}
                </label>
              ))}
            </div>
          </Field>
        )}
        {err && <ErrorBox error={err} />}
        <div className="flex justify-end gap-2 pt-1">
          <button className="btn-ghost" onClick={onClose}>Cancel</button>
          <button className="btn-primary" disabled={!name || days === 0 || (targetKind !== 'all' && !targetId)} onClick={save}>Save</button>
        </div>
      </div>
    </Modal>
  )
}

function minToHMS(m: number): string {
  return `${String(Math.floor(m / 60)).padStart(2, '0')}:${String(m % 60).padStart(2, '0')}`
}
