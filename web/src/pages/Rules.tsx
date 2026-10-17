import { useEffect, useState } from 'react'
import { Plus, Download, Upload, FlaskConical, Pencil, Trash2, Search } from 'lucide-react'
import { api } from '../lib/api'
import { Rule, Client, Decision } from '../lib/types'
import { Badge, EmptyState, ErrorBox, Loading, Modal, Field, Toggle } from '../components/ui'

export function Rules() {
  const [items, setItems] = useState<Rule[] | null>(null)
  const [clients, setClients] = useState<Client[]>([])
  const [err, setErr] = useState<unknown>(null)
  const [search, setSearch] = useState('')
  const [edit, setEdit] = useState<Rule | 'new' | null>(null)
  const [testOpen, setTestOpen] = useState(false)
  const [importOpen, setImportOpen] = useState(false)

  const load = () => {
    api.get<Rule[]>('/api/v1/rules').then(r => setItems(r ?? [])).catch(setErr)
    api.get<Client[]>('/api/v1/clients').then(r => setClients(r ?? [])).catch(() => {})
  }
  useEffect(() => { load() }, [])

  const toggle = async (r: Rule) => {
    await api.patch(`/api/v1/rules/${r.id}`, { enabled: !r.enabled }).then(load).catch(setErr)
  }
  const del = async (r: Rule) => {
    if (!confirm(`Delete ${r.action} rule for ${r.domain}?`)) return
    await api.del(`/api/v1/rules/${r.id}`).then(load).catch(setErr)
  }

  if (!items) return err ? <ErrorBox error={err} /> : <Loading />
  const filtered = items.filter(r => !search || r.domain.includes(search.toLowerCase()))
  const clientName = (id: number) => id === 0 ? 'all clients' : (clients.find(c => c.id === id)?.alias || `client #${id}`)

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-lg font-semibold text-zinc-100">Custom Rules</h1>
        <div className="flex gap-2">
          <button className="btn-ghost" onClick={() => setTestOpen(true)}><FlaskConical className="h-3.5 w-3.5" /> Test domain</button>
          <button className="btn-ghost" onClick={() => setImportOpen(true)}><Upload className="h-3.5 w-3.5" /> Import</button>
          <button className="btn-ghost" onClick={() => window.open('/api/v1/rules/export', '_blank')}><Download className="h-3.5 w-3.5" /> Export</button>
          <button className="btn-primary" onClick={() => setEdit('new')}><Plus className="h-3.5 w-3.5" /> Add rule</button>
        </div>
      </div>

      <div className="card flex items-center gap-2 p-3">
        <div className="relative">
          <Search className="absolute left-2.5 top-2 h-3.5 w-3.5 text-zinc-500" />
          <input className="input pl-8 w-64" placeholder="Search rules…" value={search} onChange={e => setSearch(e.target.value)} />
        </div>
        <span className="text-xs text-zinc-600">{filtered.length} of {items.length} rules</span>
      </div>

      <ErrorBox error={err} />
      {items.length === 0 ? (
        <EmptyState title="No custom rules" hint={'Custom allow/block rules take precedence over blocklists. A "*.domain" entry matches all subdomains.'} />
      ) : (
        <div className="card overflow-x-auto">
          <table className="w-full min-w-[720px]">
            <thead><tr>
              <th className="th">Domain</th><th className="th">Action</th><th className="th">Scope</th>
              <th className="th">Applies to</th><th className="th">Comment</th><th className="th">On</th><th className="th" />
            </tr></thead>
            <tbody>
              {filtered.map(r => (
                <tr key={r.id} className="hover:bg-zinc-800/30">
                  <td className="td font-mono text-xs">{r.scope === 'tree' ? '*.' + r.domain : r.domain}</td>
                  <td className="td">{r.action === 'block' ? <Badge tone="bad">block</Badge> : <Badge tone="ok">allow</Badge>}</td>
                  <td className="td text-xs text-zinc-500">{r.scope === 'tree' ? 'domain + subdomains' : 'exact only'}</td>
                  <td className="td text-xs text-zinc-500">{clientName(r.client_id)}</td>
                  <td className="td max-w-[200px] truncate text-xs text-zinc-500">{r.comment || '—'}</td>
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

      {edit && <RuleModal rule={edit === 'new' ? null : edit} clients={clients} onClose={() => setEdit(null)} onSaved={() => { setEdit(null); load() }} />}
      {testOpen && <TestModal clients={clients} onClose={() => setTestOpen(false)} />}
      {importOpen && <ImportModal onClose={() => setImportOpen(false)} onSaved={() => { setImportOpen(false); load() }} />}
    </div>
  )
}

function RuleModal({ rule, clients, onClose, onSaved }: {
  rule: Rule | null; clients: Client[]; onClose: () => void; onSaved: () => void
}) {
  const [domain, setDomain] = useState(rule?.domain || '')
  const [action, setAction] = useState<'allow' | 'block'>(rule?.action || 'block')
  const [scope, setScope] = useState<'exact' | 'tree'>(rule?.scope || 'exact')
  const [clientId, setClientId] = useState(rule?.client_id || 0)
  const [comment, setComment] = useState(rule?.comment || '')
  const [err, setErr] = useState('')
  const save = async () => {
    try {
      if (rule) {
        await api.patch(`/api/v1/rules/${rule.id}`, { domain, action, scope, client_id: clientId, comment })
      } else {
        await api.post('/api/v1/rules', { domain, action, scope, client_id: clientId, comment })
      }
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
        <Field label="Applies to">
          <select className="input w-full" value={clientId} onChange={e => setClientId(Number(e.target.value))}>
            <option value={0}>All clients</option>
            {clients.map(c => <option key={c.id} value={c.id}>{c.alias || c.ip}</option>)}
          </select>
        </Field>
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

function TestModal({ clients, onClose }: { clients: Client[]; onClose: () => void }) {
  const [domain, setDomain] = useState('')
  const [clientId, setClientId] = useState(0)
  const [res, setRes] = useState<Decision | null>(null)
  const [err, setErr] = useState('')
  const run = async () => {
    setErr('')
    try { setRes(await api.post<Decision>('/api/v1/rules/test', { domain, client_id: clientId })) }
    catch (e) { setErr(e instanceof Error ? e.message : String(e)) }
  }
  return (
    <Modal title="Test domain against rules" onClose={onClose}>
      <div className="space-y-3">
        <Field label="Domain"><input className="input w-full font-mono" value={domain} onChange={e => setDomain(e.target.value)} placeholder="ads.example.com" /></Field>
        <Field label="Client">
          <select className="input w-full" value={clientId} onChange={e => setClientId(Number(e.target.value))}>
            <option value={0}>Any client</option>
            {clients.map(c => <option key={c.id} value={c.id}>{c.alias || c.ip}</option>)}
          </select>
        </Field>
        <button className="btn-primary" disabled={!domain} onClick={run}>Test</button>
        {err && <ErrorBox error={err} />}
        {res && (
          <div className="rounded-md border border-zinc-800 bg-zinc-950/50 p-3 text-sm">
            <div className="flex items-center gap-2">
              {res.blocked ? <Badge tone="bad">blocked</Badge> : <Badge tone="ok">allowed</Badge>}
              <span className="text-zinc-400">{res.reason}</span>
            </div>
            {res.rule && (
              <div className="mt-2 text-xs text-zinc-500 font-mono">
                rule #{res.rule.id}: {res.rule.action} {res.rule.scope === 'tree' ? '*.' : ''}{res.rule.domain}
                {res.rule.client_id ? ` (client ${res.rule.client_id})` : ''}
              </div>
            )}
            {res.list_id ? <div className="mt-1 text-xs text-zinc-500">matched blocklist #{res.list_id}</div> : null}
          </div>
        )}
        <p className="text-xs text-zinc-600">
          Precedence: exact allow → exact block → most-specific custom rule → blocklist exception → blocklist → allowed by default.
        </p>
      </div>
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
