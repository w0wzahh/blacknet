import { useEffect, useState } from 'react'
import { Plus, Download, Upload, FlaskConical, Pencil, Trash2, Search, SearchCode, ListChecks, GitCompareArrows, Clock } from 'lucide-react'
import { api, fmtTime } from '../lib/api'
import { Rule, Client, PolicyGroup, InspectResult, BatchResult, RuleConflict } from '../lib/types'
import { Badge, EmptyState, ErrorBox, Loading, Modal, Field, Toggle, PageHeader } from '../components/ui'
import { ExplanationView } from './Policies'

export function Rules() {
  const [items, setItems] = useState<Rule[] | null>(null)
  const [clients, setClients] = useState<Client[]>([])
  const [groups, setGroups] = useState<PolicyGroup[]>([])
  const [err, setErr] = useState<unknown>(null)
  const [search, setSearch] = useState('')
  const [edit, setEdit] = useState<Rule | 'new' | null>(null)
  const [testOpen, setTestOpen] = useState(false)
  const [importOpen, setImportOpen] = useState(false)
  const [inspectOpen, setInspectOpen] = useState(false)
  const [batchOpen, setBatchOpen] = useState(false)
  const [conflicts, setConflicts] = useState<RuleConflict[] | null>(null)

  const load = () => {
    api.get<Rule[]>('/api/v1/rules').then(r => setItems(r ?? [])).catch(setErr)
    api.get<Client[]>('/api/v1/clients').then(r => setClients(r ?? [])).catch(() => {})
    api.get<PolicyGroup[]>('/api/v1/policies/groups').then(r => setGroups(r ?? [])).catch(() => {})
  }
  useEffect(() => { load() }, [])

  const toggle = async (r: Rule) => {
    await api.patch(`/api/v1/rules/${r.id}`, { enabled: !r.enabled }).then(load).catch(setErr)
  }
  const del = async (r: Rule) => {
    if (!confirm(`Delete ${r.action} rule for ${r.domain}?`)) return
    await api.del(`/api/v1/rules/${r.id}`).then(load).catch(setErr)
  }
  const showConflicts = async () => {
    setConflicts(await api.get<RuleConflict[]>('/api/v1/rules/conflicts'))
  }

  if (!items) return err ? <ErrorBox error={err} /> : <Loading />
  const filtered = items.filter(r => !search || r.domain.includes(search.toLowerCase()))
  const appliesTo = (r: Rule) => {
    if (r.client_id) return clients.find(c => c.id === r.client_id)?.alias || `client #${r.client_id}`
    if (r.group_id) return 'group: ' + (groups.find(g => g.id === r.group_id)?.name || `#${r.group_id}`)
    return 'everyone'
  }
  const isTemp = (r: Rule) => !!r.expires_at
  const expired = (r: Rule) => r.expires_at ? new Date(r.expires_at) < new Date() : false

  return (
    <div className="space-y-4">
      <PageHeader title="Custom Rules" desc="Allow and block rules, scoped globally, per client, or per policy group.">
        <div className="flex flex-wrap gap-2">
          <button className="btn-ghost" onClick={() => setInspectOpen(true)}><SearchCode className="h-3.5 w-3.5" /> Inspect</button>
          <button className="btn-ghost" onClick={() => setBatchOpen(true)}><ListChecks className="h-3.5 w-3.5" /> Batch test</button>
          <button className="btn-ghost" onClick={() => setTestOpen(true)}><FlaskConical className="h-3.5 w-3.5" /> Test</button>
          <button className="btn-ghost" onClick={showConflicts}><GitCompareArrows className="h-3.5 w-3.5" /> Conflicts</button>
          <button className="btn-ghost" onClick={() => setImportOpen(true)}><Upload className="h-3.5 w-3.5" /> Import</button>
          <button className="btn-ghost" onClick={() => window.open('/api/v1/rules/export', '_blank')}><Download className="h-3.5 w-3.5" /> Export</button>
          <button className="btn-primary" onClick={() => setEdit('new')}><Plus className="h-3.5 w-3.5" /> Add rule</button>
        </div>
      </PageHeader>

      <div className="card flex items-center gap-2 p-3">
        <div className="relative">
          <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-zinc-500" />
          <input className="input pl-8 w-64" placeholder="Search rules…" value={search} onChange={e => setSearch(e.target.value)} />
        </div>
        <span className="text-xs text-zinc-600">{filtered.length} of {items.length} rules</span>
      </div>

      <ErrorBox error={err} />
      {items.length === 0 ? (
        <EmptyState title="No custom rules" hint={'Custom allow/block rules take precedence over blocklists. A "*.domain" entry matches all subdomains.'} />
      ) : (
        <div className="card overflow-x-auto">
          <table className="w-full min-w-[800px]">
            <thead><tr>
              <th className="th">Domain</th><th className="th">Action</th><th className="th">Scope</th>
              <th className="th">Applies to</th><th className="th">Expires</th><th className="th">Comment</th>
              <th className="th">On</th><th className="th" />
            </tr></thead>
            <tbody>
              {filtered.map(r => (
                <tr key={r.id} className={`hover:bg-zinc-800/30 ${expired(r) ? 'opacity-40' : ''}`}>
                  <td className="td font-mono text-xs">{r.scope === 'tree' ? '*.' + r.domain : r.domain}</td>
                  <td className="td">{r.action === 'block' ? <Badge tone="bad">block</Badge> : <Badge tone="ok">allow</Badge>}</td>
                  <td className="td text-xs text-zinc-500">{r.scope === 'tree' ? 'domain + subdomains' : 'exact only'}</td>
                  <td className="td text-xs text-zinc-500">{appliesTo(r)}</td>
                  <td className="td text-xs whitespace-nowrap">
                    {isTemp(r)
                      ? <span className={expired(r) ? 'text-zinc-600' : 'text-amber-400'}><Clock className="mr-1 inline h-3 w-3" />{expired(r) ? 'expired ' : ''}{fmtTime(r.expires_at)}</span>
                      : <span className="text-zinc-700">—</span>}
                  </td>
                  <td className="td max-w-[160px] truncate text-xs text-zinc-500">{r.comment || '—'}</td>
                  <td className="td"><Toggle on={r.enabled} onChange={() => toggle(r)} /></td>
                  <td className="td">
                    <div className="flex justify-end gap-1">
                      <button className="btn-ghost px-2!" onClick={() => setEdit(r)}><Pencil className="h-3.5 w-3.5" /></button>
                      <button className="btn-subtle-danger px-2!" onClick={() => del(r)}><Trash2 className="h-3.5 w-3.5" /></button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {edit && <RuleModal rule={edit === 'new' ? null : edit} clients={clients} groups={groups}
        onClose={() => setEdit(null)} onSaved={() => { setEdit(null); load() }} />}
      {testOpen && <TestModal clients={clients} groups={groups} onClose={() => setTestOpen(false)} />}
      {importOpen && <ImportModal onClose={() => setImportOpen(false)} onSaved={() => { setImportOpen(false); load() }} />}
      {inspectOpen && <InspectModal clients={clients} groups={groups} onClose={() => setInspectOpen(false)} />}
      {batchOpen && <BatchModal clients={clients} groups={groups} onClose={() => setBatchOpen(false)} />}
      {conflicts && <ConflictsModal conflicts={conflicts} onClose={() => setConflicts(null)} />}
    </div>
  )
}

function RuleModal({ rule, clients, groups, onClose, onSaved }: {
  rule: Rule | null; clients: Client[]; groups: PolicyGroup[]; onClose: () => void; onSaved: () => void
}) {
  const [domain, setDomain] = useState(rule?.domain || '')
  const [action, setAction] = useState<'allow' | 'block'>(rule?.action || 'block')
  const [scope, setScope] = useState<'exact' | 'tree'>(rule?.scope || 'exact')
  const [clientId, setClientId] = useState(rule?.client_id || 0)
  const [groupId, setGroupId] = useState(rule?.group_id || 0)
  const [comment, setComment] = useState(rule?.comment || '')
  const [ttlMin, setTtlMin] = useState(0)
  const [err, setErr] = useState('')
  const save = async () => {
    try {
      const body: any = { domain, action, scope, client_id: clientId, group_id: groupId, comment }
      if (!rule && ttlMin > 0) body.expires_at = new Date(Date.now() + ttlMin * 60000).toISOString()
      if (rule) await api.patch(`/api/v1/rules/${rule.id}`, body)
      else await api.post('/api/v1/rules', body)
      onSaved()
    } catch (e) { setErr(e instanceof Error ? e.message : String(e)) }
  }
  return (
    <Modal title={rule ? 'Edit rule' : 'Add rule'} onClose={onClose}>
      <div className="space-y-3">
        <Field label="Domain" hint='Prefix with "*." or pick "domain + subdomains" scope to cover subdomains.'>
          <input className="input w-full font-mono" value={domain} onChange={e => setDomain(e.target.value)} placeholder="ads.example.com" />
        </Field>
        <div className="grid grid-cols-2 gap-3">
          <Field label="Action">
            <select className="input w-full" value={action} onChange={e => setAction(e.target.value as any)}>
              <option value="block">Block</option>
              <option value="allow">Allow</option>
            </select>
          </Field>
          <Field label="Scope">
            <select className="input w-full" value={scope} onChange={e => setScope(e.target.value as any)}>
              <option value="exact">Exact domain only</option>
              <option value="tree">Domain + subdomains</option>
            </select>
          </Field>
        </div>
        <div className="grid grid-cols-2 gap-3">
          <Field label="Specific client" hint="Optional.">
            <select className="input w-full" value={clientId} onChange={e => setClientId(Number(e.target.value))}>
              <option value={0}>Any client</option>
              {clients.map(c => <option key={c.id} value={c.id}>{c.alias || c.ip}</option>)}
            </select>
          </Field>
          <Field label="Specific group" hint="Optional.">
            <select className="input w-full" value={groupId} onChange={e => setGroupId(Number(e.target.value))}>
              <option value={0}>Any group</option>
              {groups.map(g => <option key={g.id} value={g.id}>{g.name}</option>)}
            </select>
          </Field>
        </div>
        {!rule && (
          <Field label="Temporary" hint="Auto-expire after N minutes; 0 = permanent.">
            <input className="input w-full" type="number" min={0} value={ttlMin} onChange={e => setTtlMin(Number(e.target.value))} />
          </Field>
        )}
        <Field label="Comment"><input className="input w-full" value={comment} onChange={e => setComment(e.target.value)} /></Field>
        {err && <ErrorBox error={err} />}
        <div className="flex justify-end gap-2 pt-1">
          <button className="btn-ghost" onClick={onClose}>Cancel</button>
          <button className="btn-primary" disabled={!domain} onClick={save}>Save</button>
        </div>
      </div>
    </Modal>
  )
}

function SubjectFields({ clients, groups, clientId, groupId, setClientId, setGroupId }: {
  clients: Client[]; groups: PolicyGroup[]
  clientId: number; groupId: number
  setClientId: (v: number) => void; setGroupId: (v: number) => void
}) {
  return (
    <div className="grid grid-cols-2 gap-3">
      <Field label="Client">
        <select className="input w-full" value={clientId} onChange={e => setClientId(Number(e.target.value))}>
          <option value={0}>Any</option>
          {clients.map(c => <option key={c.id} value={c.id}>{c.alias || c.ip}</option>)}
        </select>
      </Field>
      <Field label="Group">
        <select className="input w-full" value={groupId} onChange={e => setGroupId(Number(e.target.value))}>
          <option value={0}>None</option>
          {groups.map(g => <option key={g.id} value={g.id}>{g.name}</option>)}
        </select>
      </Field>
    </div>
  )
}

function TestModal({ clients, groups, onClose }: { clients: Client[]; groups: PolicyGroup[]; onClose: () => void }) {
  const [domain, setDomain] = useState('')
  const [clientId, setClientId] = useState(0)
  const [groupId, setGroupId] = useState(0)
  const [res, setRes] = useState<any>(null)
  const [err, setErr] = useState('')
  const run = async () => {
    setErr('')
    try {
      setRes(await api.post('/api/v1/rules/test', { domain, client_id: clientId, group_id: groupId || undefined }))
    } catch (e) { setErr(e instanceof Error ? e.message : String(e)) }
  }
  const ex = res?.explanation ?? res
  return (
    <Modal title="Test domain against rules" onClose={onClose}>
      <div className="space-y-3">
        <Field label="Domain"><input className="input w-full font-mono" value={domain} onChange={e => setDomain(e.target.value)} placeholder="ads.example.com" /></Field>
        <SubjectFields clients={clients} groups={groups} clientId={clientId} groupId={groupId} setClientId={setClientId} setGroupId={setGroupId} />
        <button className="btn-primary" disabled={!domain} onClick={run}>Test</button>
        {err && <ErrorBox error={err} />}
        {ex && ex.decision && <ExplanationView ex={ex} />}
        <p className="text-xs text-zinc-600">
          Precedence: client/group rules → global rules → blocklist exceptions → blocklists → default allow.
        </p>
      </div>
    </Modal>
  )
}

function InspectModal({ clients, groups, onClose }: { clients: Client[]; groups: PolicyGroup[]; onClose: () => void }) {
  const [domain, setDomain] = useState('')
  const [clientId, setClientId] = useState(0)
  const [groupId, setGroupId] = useState(0)
  const [res, setRes] = useState<InspectResult | null>(null)
  const [err, setErr] = useState('')
  const run = async () => {
    setErr('')
    try {
      const q = new URLSearchParams({ domain })
      if (clientId) q.set('client_id', String(clientId))
      if (groupId) q.set('group_id', String(groupId))
      setRes(await api.get<InspectResult>(`/api/v1/rules/inspect?${q}`))
    } catch (e) { setErr(e instanceof Error ? e.message : String(e)) }
  }
  return (
    <Modal title="Inspect domain" onClose={onClose} wide>
      <div className="space-y-3">
        <Field label="Domain"><input className="input w-full font-mono" value={domain} onChange={e => setDomain(e.target.value)} placeholder="tracker.example.com" /></Field>
        <SubjectFields clients={clients} groups={groups} clientId={clientId} groupId={groupId} setClientId={setClientId} setGroupId={setGroupId} />
        <button className="btn-primary" disabled={!domain} onClick={run}>Inspect</button>
        {err && <ErrorBox error={err} />}
        {res && (
          <div className="space-y-3">
            <ExplanationView ex={res.explanation} />
            {(res.matched_rules ?? []).length > 0 && (
              <div>
                <div className="mb-1 text-xs font-medium text-zinc-400">All matching rules (precedence order)</div>
                <div className="space-y-1">
                  {(res.matched_rules ?? []).map(r => (
                    <div key={r.id} className="flex items-center gap-2 rounded border border-zinc-800 px-2 py-1 text-xs">
                      {r.action === 'block' ? <Badge tone="bad">block</Badge> : <Badge tone="ok">allow</Badge>}
                      <span className="font-mono">{r.scope === 'tree' ? '*.' : ''}{r.domain}</span>
                      <span className="text-zinc-600">#{r.id}</span>
                      {r.client_id !== 0 && <Badge tone="muted">client {r.client_id}</Badge>}
                      {r.group_id !== 0 && <Badge tone="accent">group {r.group_id}</Badge>}
                    </div>
                  ))}
                </div>
              </div>
            )}
            <div className="grid grid-cols-2 gap-3 text-xs">
              <div>
                <div className="mb-1 font-medium text-zinc-400">Found in blocklists</div>
                {(res.in_blocklists ?? []).length === 0 ? <div className="text-zinc-600">none</div> :
                  res.in_blocklists.map((b, i) => (
                    <div key={i} className="font-mono text-zinc-300">{b.name || `#${b.list_id}`} <span className="text-zinc-600">via {b.matched_domain}</span></div>
                  ))}
              </div>
              <div>
                <div className="mb-1 font-medium text-zinc-400">Exceptions</div>
                {(res.exceptions ?? []).length === 0 ? <div className="text-zinc-600">none</div> :
                  res.exceptions.map((b, i) => (
                    <div key={i} className="font-mono text-zinc-300">{b.name || `#${b.list_id}`} <span className="text-zinc-600">via {b.matched_domain}</span></div>
                  ))}
              </div>
            </div>
          </div>
        )}
      </div>
    </Modal>
  )
}

function BatchModal({ clients, groups, onClose }: { clients: Client[]; groups: PolicyGroup[]; onClose: () => void }) {
  const [text, setText] = useState('')
  const [clientId, setClientId] = useState(0)
  const [groupId, setGroupId] = useState(0)
  const [res, setRes] = useState<BatchResult | null>(null)
  const [err, setErr] = useState('')
  const run = async () => {
    setErr('')
    try {
      setRes(await api.post<BatchResult>('/api/v1/rules/batch-test',
        { text, client_id: clientId, group_id: groupId || undefined }))
    } catch (e) { setErr(e instanceof Error ? e.message : String(e)) }
  }
  return (
    <Modal title="Batch test domains" onClose={onClose} wide>
      <div className="space-y-3">
        <Field label="Domains" hint="One per line, up to 1000.">
          <textarea className="input h-32 w-full font-mono text-xs" value={text} onChange={e => setText(e.target.value)} />
        </Field>
        <SubjectFields clients={clients} groups={groups} clientId={clientId} groupId={groupId} setClientId={setClientId} setGroupId={setGroupId} />
        <button className="btn-primary" disabled={!text.trim()} onClick={run}>Test all</button>
        {err && <ErrorBox error={err} />}
        {res && (
          <div className="max-h-64 overflow-y-auto rounded border border-zinc-800">
            <table className="w-full">
              <thead className="sticky top-0 bg-zinc-900"><tr><th className="th">Domain</th><th className="th">Decision</th><th className="th">Reason</th></tr></thead>
              <tbody>
                {(res.results ?? []).map((r, i) => (
                  <tr key={i} className="hover:bg-zinc-800/30">
                    <td className="td font-mono text-xs">{r.domain}</td>
                    <td className="td">{r.blocked ? <Badge tone="bad">blocked</Badge> : <Badge tone="muted">allowed</Badge>}</td>
                    <td className="td text-xs text-zinc-500">{r.reason}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </Modal>
  )
}

function ConflictsModal({ conflicts, onClose }: { conflicts: RuleConflict[]; onClose: () => void }) {
  const tone = (r: string) => r === 'conflict' ? 'bad' : r === 'shadowed' ? 'warn' : 'muted'
  return (
    <Modal title="Rule conflicts" onClose={onClose} wide>
      {conflicts.length === 0 ? (
        <div className="py-6 text-center text-sm text-zinc-500">No conflicts between enabled rules.</div>
      ) : (
        <div className="max-h-80 space-y-2 overflow-y-auto">
          {conflicts.map((c, i) => (
            <div key={i} className="flex items-start gap-3 rounded border border-zinc-800 px-3 py-2 text-xs">
              <Badge tone={tone(c.relation)}>{c.relation}</Badge>
              <div>
                <span className="font-mono text-zinc-200">{c.domain}</span>{' '}
                <span className="text-zinc-600">rule #{c.rule_id}</span>
                <div className="mt-0.5 text-zinc-500">{c.detail}</div>
              </div>
            </div>
          ))}
        </div>
      )}
      <div className="flex justify-end pt-3"><button className="btn-ghost" onClick={onClose}>Close</button></div>
    </Modal>
  )
}

function ImportModal({ onClose, onSaved }: { onClose: () => void; onSaved: () => void }) {
  const [text, setText] = useState('')
  const [res, setRes] = useState<{ added: number; skipped_duplicates: number; errors: string[] } | null>(null)
  const run = async () => {
    setRes(await api.post('/api/v1/rules/import', { text }))
  }
  return (
    <Modal title="Import rules" onClose={onClose} wide>
      <div className="space-y-3">
        <p className="text-xs text-zinc-500">
          One rule per line: <code className="font-mono text-zinc-400">block ads.example.com</code> or{' '}
          <code className="font-mono text-zinc-400">allow *.ok.example.com</code>. Lines starting with # are comments.
        </p>
        <textarea className="input h-40 w-full font-mono text-xs" value={text} onChange={e => setText(e.target.value)} />
        {res && (
          <div className="text-xs text-zinc-400">
            Added {res.added}, skipped {res.skipped_duplicates} duplicates.
            {res.errors.length > 0 && <pre className="mt-1 max-h-24 overflow-auto text-red-400">{res.errors.join('\n')}</pre>}
          </div>
        )}
        <div className="flex justify-end gap-2 pt-1">
          <button className="btn-ghost" onClick={onClose}>Close</button>
          <button className="btn-primary" onClick={run} disabled={!text.trim()}>Import</button>
          {res && <button className="btn-primary" onClick={onSaved}>Done</button>}
        </div>
      </div>
    </Modal>
  )
}
