import { useEffect, useState } from 'react'
import { Plus, RefreshCw, Trash2, History, Users, Sparkles, GitCompareArrows, AlertTriangle } from 'lucide-react'
import { api, fmtNum, fmtTime } from '../lib/api'
import { Blocklist, ListHistoryEntry, PolicyGroup } from '../lib/types'
import { Badge, EmptyState, ErrorBox, Loading, Modal, Field, Toggle, PageHeader } from '../components/ui'

interface Profile {
  id: string; name: string; description: string; risk: string
  lists: { name: string; url: string }[]
}
interface Recs {
  overlaps: { a: number; a_name: string; b: number; b_name: string; shared: number; pct_of_smaller: number }[]
  warnings: { list_id: number; name: string; issue: string }[]
  counts: { enabled_lists: number }
}

export function Blocklists() {
  const [items, setItems] = useState<Blocklist[] | null>(null)
  const [groups, setGroups] = useState<PolicyGroup[]>([])
  const [listGroups, setListGroups] = useState<Record<number, number[]>>({})
  const [err, setErr] = useState<unknown>(null)
  const [addOpen, setAddOpen] = useState(false)
  const [profilesOpen, setProfilesOpen] = useState(false)
  const [recs, setRecs] = useState<Recs | null>(null)
  const [history, setHistory] = useState<Blocklist | null>(null)
  const [groupEdit, setGroupEdit] = useState<Blocklist | null>(null)
  const [refreshing, setRefreshing] = useState<number | null>(null)
  const [notice, setNotice] = useState('')

  const load = () => {
    api.get<Blocklist[]>('/api/v1/blocklists').then(r => setItems(r ?? [])).catch(setErr)
    api.get<PolicyGroup[]>('/api/v1/policies/groups').then(r => setGroups(r ?? [])).catch(() => {})
  }
  useEffect(() => { load() }, [])

  const loadGroupMap = async (lists: Blocklist[]) => {
    const m: Record<number, number[]> = {}
    await Promise.all(lists.map(l =>
      api.get<{ group_ids: number[] }>(`/api/v1/blocklists/${l.id}/groups`)
        .then(r => { m[l.id] = r.group_ids ?? [] }).catch(() => {})))
    setListGroups(m)
  }
  useEffect(() => { if (items && groups.length > 0 && Object.keys(listGroups).length === 0) loadGroupMap(items) }, [items, groups])

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
  const showRecs = async () => setRecs(await api.get<Recs>('/api/v1/blocklists/recommendations'))

  if (!items) return err ? <ErrorBox error={err} /> : <Loading />
  const scopeLabel = (b: Blocklist) => {
    const gids = listGroups[b.id]
    if (!gids || gids.length === 0) return 'all groups'
    return 'groups: ' + gids.map(id => groups.find(g => g.id === id)?.name || `#${id}`).join(', ')
  }

  return (
    <div className="space-y-4">
      <PageHeader title="Blocklists" desc="Curated domain lists imported and refreshed on a schedule.">
        <div className="flex gap-2">
          <button className="btn-ghost" onClick={() => setProfilesOpen(true)}><Sparkles className="h-3.5 w-3.5" /> Profiles</button>
          <button className="btn-ghost" onClick={showRecs}><GitCompareArrows className="h-3.5 w-3.5" /> Insights</button>
          <button className="btn-primary" onClick={() => setAddOpen(true)}><Plus className="h-3.5 w-3.5" /> Add list</button>
        </div>
      </PageHeader>
      <ErrorBox error={err} />
      {notice && <div className="rounded-md border border-emerald-800/60 bg-emerald-950/40 px-3 py-2 text-sm text-emerald-300">{notice}</div>}
      {items.length === 0 ? (
        <EmptyState title="No blocklists" hint="Add a blocklist URL or apply a curated profile to start importing domains." />
      ) : (
        <div className="card overflow-x-auto">
          <table className="w-full min-w-[860px]">
            <thead><tr>
              <th className="th">Name</th><th className="th">Source</th><th className="th">Scope</th><th className="th">On</th>
              <th className="th">Last refresh</th><th className="th text-right">Rules</th>
              <th className="th">Error</th><th className="th" />
            </tr></thead>
            <tbody>
              {items.map(b => (
                <tr key={b.id} className="hover:bg-zinc-800/30">
                  <td className="td font-medium text-zinc-200">{b.name}</td>
                  <td className="td max-w-[220px] truncate font-mono text-xs text-zinc-500" title={b.url}>{b.url}</td>
                  <td className="td text-xs text-zinc-500">{scopeLabel(b)}</td>
                  <td className="td"><Toggle on={b.enabled} onChange={() => toggle(b)} /></td>
                  <td className="td text-xs text-zinc-500 whitespace-nowrap">{b.last_refresh ? fmtTime(b.last_refresh) : 'never'}</td>
                  <td className="td text-right tabular-nums">{fmtNum(b.rule_count)}</td>
                  <td className="td max-w-[160px] truncate text-xs text-red-400" title={b.last_error}>{b.last_error || '—'}</td>
                  <td className="td">
                    <div className="flex justify-end gap-1">
                      <button className="btn-ghost px-2!" title="Update history" onClick={() => setHistory(b)}><History className="h-3.5 w-3.5" /></button>
                      <button className="btn-ghost px-2!" title="Restrict to groups" onClick={() => setGroupEdit(b)}><Users className="h-3.5 w-3.5" /></button>
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
      {profilesOpen && <ProfilesModal onClose={() => setProfilesOpen(false)} onApplied={() => { setProfilesOpen(false); load() }} />}
      {history && <HistoryModal list={history} onClose={() => setHistory(null)} />}
      {groupEdit && <GroupScopeModal list={groupEdit} groups={groups} current={listGroups[groupEdit.id] ?? []}
        onClose={() => setGroupEdit(null)}
        onSaved={() => { setListGroups({}); setGroupEdit(null); load() }} />}
      {recs && <RecsModal recs={recs} onClose={() => setRecs(null)} />}
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

function ProfilesModal({ onClose, onApplied }: { onClose: () => void; onApplied: () => void }) {
  const [profiles, setProfiles] = useState<Profile[] | null>(null)
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState('')
  useEffect(() => {
    api.get<Profile[]>('/api/v1/blocklists/profiles').then(r => setProfiles(r ?? [])).catch(e => setErr(String(e)))
  }, [])
  const apply = async (p: Profile) => {
    setBusy(p.id); setErr('')
    try { await api.post('/api/v1/blocklists/profile', { profile: p.id }); onApplied() }
    catch (e) { setErr(e instanceof Error ? e.message : String(e)); setBusy('') }
  }
  const riskTone = (r: string) => r === 'low' ? 'ok' : r === 'medium' ? 'warn' : 'bad'
  return (
    <Modal title="Curated profiles" onClose={onClose} wide>
      {!profiles ? <Loading /> : (
        <div className="space-y-3">
          <p className="text-xs text-zinc-500">A profile enables a bundle of well-known lists. Existing lists are kept.</p>
          {profiles.map(p => (
            <div key={p.id} className="card flex items-center justify-between gap-4 p-3">
              <div>
                <div className="flex items-center gap-2">
                  <span className="font-medium text-zinc-100">{p.name}</span>
                  <Badge tone={riskTone(p.risk)}>{p.risk} risk</Badge>
                </div>
                <div className="mt-1 text-xs text-zinc-500">{p.description}</div>
                <div className="mt-1 text-xs text-zinc-600">{p.lists.length} list{p.lists.length === 1 ? '' : 's'}</div>
              </div>
              <button className="btn-primary shrink-0" disabled={busy !== ''} onClick={() => apply(p)}>
                {busy === p.id ? 'Applying…' : 'Apply'}
              </button>
            </div>
          ))}
          {err && <ErrorBox error={err} />}
        </div>
      )}
    </Modal>
  )
}

function HistoryModal({ list, onClose }: { list: Blocklist; onClose: () => void }) {
  const [items, setItems] = useState<ListHistoryEntry[] | null>(null)
  useEffect(() => {
    api.get<ListHistoryEntry[]>(`/api/v1/blocklists/${list.id}/history?limit=30`)
      .then(r => setItems(r ?? [])).catch(() => setItems([]))
  }, [list.id])
  return (
    <Modal title={`Update history — ${list.name}`} onClose={onClose} wide>
      {!items ? <Loading /> : items.length === 0 ? (
        <div className="py-6 text-center text-xs text-zinc-600">No refreshes recorded yet.</div>
      ) : (
        <div className="max-h-80 overflow-y-auto">
          <table className="w-full">
            <thead><tr>
              <th className="th">Time</th><th className="th">Status</th><th className="th text-right">Rules</th>
              <th className="th text-right">Bytes</th><th className="th text-right">Malformed</th>
              <th className="th text-right">Duplicates</th><th className="th">Error</th>
            </tr></thead>
            <tbody>
              {items.map(h => (
                <tr key={h.id}>
                  <td className="td text-xs text-zinc-500 whitespace-nowrap">{fmtTime(h.ts)}</td>
                  <td className="td"><Badge tone={h.status === 'ok' ? 'ok' : h.status === 'unchanged' ? 'muted' : 'bad'}>{h.status}</Badge></td>
                  <td className="td text-right tabular-nums text-xs">{fmtNum(h.rule_count)}</td>
                  <td className="td text-right tabular-nums text-xs">{fmtNum(h.bytes)}</td>
                  <td className="td text-right tabular-nums text-xs">{h.malformed > 0 ? <span className="text-amber-400">{fmtNum(h.malformed)}</span> : '0'}</td>
                  <td className="td text-right tabular-nums text-xs">{fmtNum(h.duplicates)}</td>
                  <td className="td max-w-[180px] truncate text-xs text-red-400" title={h.error}>{h.error || '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Modal>
  )
}

function GroupScopeModal({ list, groups, current, onClose, onSaved }: {
  list: Blocklist; groups: PolicyGroup[]; current: number[]; onClose: () => void; onSaved: () => void
}) {
  const [sel, setSel] = useState<number[]>(current)
  const [err, setErr] = useState('')
  const save = async () => {
    try { await api.put(`/api/v1/blocklists/${list.id}/groups`, { group_ids: sel }); onSaved() }
    catch (e) { setErr(e instanceof Error ? e.message : String(e)) }
  }
  return (
    <Modal title={`Restrict "${list.name}" to groups`} onClose={onClose}>
      <div className="space-y-3">
        <p className="text-xs text-zinc-500">Unchecked = the list applies to every group (global).</p>
        <div className="max-h-48 space-y-1 overflow-y-auto rounded border border-zinc-800 p-2">
          {groups.length === 0 && <div className="text-xs text-zinc-600">No policy groups yet — create them under Policies.</div>}
          {groups.map(g => (
            <label key={g.id} className="flex items-center gap-2 text-sm text-zinc-300">
              <input type="checkbox" checked={sel.includes(g.id)}
                onChange={e => setSel(e.target.checked ? [...sel, g.id] : sel.filter(x => x !== g.id))} />
              {g.name}
            </label>
          ))}
        </div>
        {err && <ErrorBox error={err} />}
        <div className="flex justify-end gap-2 pt-1">
          <button className="btn-ghost" onClick={onClose}>Cancel</button>
          <button className="btn-primary" onClick={save}>Save</button>
        </div>
      </div>
    </Modal>
  )
}

function RecsModal({ recs, onClose }: { recs: Recs; onClose: () => void }) {
  return (
    <Modal title="Blocklist insights" onClose={onClose} wide>
      <div className="space-y-4">
        <div>
          <div className="mb-2 text-sm font-medium text-zinc-200">Overlaps between enabled lists</div>
          {recs.overlaps.length === 0 ? (
            <div className="text-xs text-zinc-600">No significant overlap.</div>
          ) : (
            <div className="space-y-1">
              {recs.overlaps.sort((a, b) => b.pct_of_smaller - a.pct_of_smaller).map((o, i) => (
                <div key={i} className="flex items-center gap-3 rounded border border-zinc-800 px-3 py-1.5 text-xs">
                  <span className="text-zinc-300">{o.a_name}</span>
                  <span className="text-zinc-600">↔</span>
                  <span className="text-zinc-300">{o.b_name}</span>
                  <span className="ml-auto text-zinc-500">{fmtNum(o.shared)} shared · {o.pct_of_smaller.toFixed(0)}% of smaller</span>
                  {o.pct_of_smaller > 70 && <Badge tone="warn">redundant</Badge>}
                </div>
              ))}
            </div>
          )}
        </div>
        <div>
          <div className="mb-2 text-sm font-medium text-zinc-200">Warnings</div>
          {recs.warnings.length === 0 ? (
            <div className="text-xs text-zinc-600">No issues detected.</div>
          ) : (
            <div className="space-y-1">
              {recs.warnings.map((w, i) => (
                <div key={i} className="flex items-start gap-2 rounded border border-amber-800/40 bg-amber-950/20 px-3 py-1.5 text-xs text-amber-300">
                  <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
                  <span><span className="font-medium">{w.name}:</span> {w.issue}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </Modal>
  )
}
