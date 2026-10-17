import { useEffect, useRef, useState } from 'react'
import { Download, Upload, RefreshCw } from 'lucide-react'
import { api, ApiError } from '../lib/api'
import { Settings, Status } from '../lib/types'
import { ErrorBox, Field, Loading, Toggle } from '../components/ui'

export function SettingsPage({ onChanged }: { onChanged?: () => void }) {
  const [s, setS] = useState<Settings | null>(null)
  const [status, setStatus] = useState<Status | null>(null)
  const [err, setErr] = useState<unknown>(null)
  const [fieldErrs, setFieldErrs] = useState<Record<string, string>>({})
  const [saved, setSaved] = useState(false)
  const fileRef = useRef<HTMLInputElement>(null)

  const load = async () => {
    try {
      setS(await api.get<Settings>('/api/v1/settings'))
      setStatus(await api.get<Status>('/api/v1/status'))
      setErr(null)
    } catch (e) { setErr(e) }
  }
  useEffect(() => { load() }, [])

  const patch = async (body: Partial<Settings>) => {
    setFieldErrs({}); setSaved(false)
    try {
      const out = await api.patch<Settings>('/api/v1/settings', body)
      setS(out); setSaved(true)
      setTimeout(() => setSaved(false), 2000)
    } catch (e) {
      setErr(e)
      if (e instanceof ApiError && e.fields) setFieldErrs(e.fields)
    }
  }

  const backup = (includeHistory: boolean) => {
    window.open(`/api/v1/backup?include_history=${includeHistory}`, '_blank')
    // POST needed — do via fetch then download
  }
  const doBackup = async (includeHistory: boolean) => {
    const res = await fetch(`/api/v1/backup?include_history=${includeHistory}`, {
      method: 'POST', headers: { 'X-Requested-With': 'XMLHttpRequest' }, credentials: 'same-origin',
    })
    if (!res.ok) { setErr(new Error('backup failed')); return }
    const blob = await res.blob()
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `blacknet-backup-${new Date().toISOString().slice(0, 10)}.zip`
    a.click()
    URL.revokeObjectURL(url)
  }

  const restore = async (file: File) => {
    if (!confirm('Restore this backup? Current settings, rules, clients and blocklists will be replaced. A safety copy of the current database is saved first.')) return
    const res = await fetch('/api/v1/restore?confirm=true', {
      method: 'POST', body: file,
      headers: { 'X-Requested-With': 'XMLHttpRequest' }, credentials: 'same-origin',
    })
    const data = await res.json().catch(() => ({}))
    if (!res.ok) { setErr(new Error(data.error || 'restore failed')); return }
    await load()
    alert('Backup restored.')
  }

  if (!s || !status) return <Loading />
  const fe = (k: string) => fieldErrs[k] ? <div className="mt-1 text-xs text-red-400">{fieldErrs[k]}</div> : null

  return (
    <div className="space-y-5 max-w-2xl">
      <div className="flex items-center justify-between">
        <h1 className="text-lg font-semibold text-zinc-100">Settings</h1>
        {saved && <span className="text-xs text-emerald-400">saved</span>}
      </div>
      <ErrorBox error={err} />

      <section className="card space-y-4 p-5">
        <h2 className="text-sm font-semibold text-zinc-200">Protection</h2>
        <div className="flex items-center justify-between">
          <div>
            <div className="text-sm text-zinc-300">DNS filtering</div>
            <div className="text-xs text-zinc-500">When off, queries resolve unfiltered. Rules and lists are preserved.</div>
          </div>
          <Toggle on={s.protection_enabled} onChange={v => patch({ protection_enabled: v })} />
        </div>
        <Field label="Blocking mode" hint="NXDOMAIN is recommended. Null mode returns 0.0.0.0/:: for A/AAAA queries.">
          <select className="input w-full" value={s.blocking_mode} onChange={e => patch({ blocking_mode: e.target.value as any })}>
            <option value="nxdomain">NXDOMAIN</option>
            <option value="null">Null IP (0.0.0.0 / ::)</option>
          </select>
        </Field>
        {fe('blocking_mode')}
        <div className="flex items-center justify-between">
          <div>
            <div className="text-sm text-zinc-300">DNSSEC upstream validation</div>
            <div className="text-xs text-zinc-500">Forward DO (DNSSEC OK) bits and record AD status on logged queries. Requires a DNSSEC-validating upstream.</div>
          </div>
          <Toggle on={s.dnssec_upstream} onChange={v => patch({ dnssec_upstream: v })} />
        </div>
      </section>

      <section className="card space-y-4 p-5">
        <h2 className="text-sm font-semibold text-zinc-200">Logging & discovery</h2>
        <div className="flex items-center justify-between">
          <div>
            <div className="text-sm text-zinc-300">Query logging</div>
            <div className="text-xs text-zinc-500">Persist every query to SQLite. Disable for maximum privacy — analytics will be empty.</div>
          </div>
          <Toggle on={s.query_logging_enabled} onChange={v => patch({ query_logging_enabled: v })} />
        </div>
        <div className="flex items-center justify-between">
          <div>
            <div className="text-sm text-zinc-300">Passive device discovery</div>
            <div className="text-xs text-zinc-500">Watch the neighbor table and DHCP leases for new devices. Nothing is probed.</div>
          </div>
          <Toggle on={s.discovery_enabled} onChange={v => patch({ discovery_enabled: v })} />
        </div>
        <div className="grid grid-cols-2 gap-3">
          <Field label="Discovery interval (s)"><input className="input w-full" type="number" value={s.discovery_interval_seconds} onChange={e => patch({ discovery_interval_seconds: Number(e.target.value) })} /></Field>
          <Field label="Audit log retention (days)"><input className="input w-full" type="number" value={s.audit_retention_days} onChange={e => patch({ audit_retention_days: Number(e.target.value) })} /></Field>
        </div>
        {fe('discovery_interval_seconds')}{fe('audit_retention_days')}
      </section>

      <section className="card space-y-4 p-5">
        <h2 className="text-sm font-semibold text-zinc-200">Cache</h2>
        <div className="flex items-center justify-between">
          <div className="text-sm text-zinc-300">Enable cache</div>
          <Toggle on={s.cache_enabled} onChange={v => patch({ cache_enabled: v })} />
        </div>
        <div className="grid grid-cols-3 gap-3">
          <Field label="Max entries"><input className="input w-full" type="number" value={s.cache_max_entries} onChange={e => patch({ cache_max_entries: Number(e.target.value) })} /></Field>
          <Field label="Min TTL (s)"><input className="input w-full" type="number" value={s.cache_min_ttl_seconds} onChange={e => patch({ cache_min_ttl_seconds: Number(e.target.value) })} /></Field>
          <Field label="Max TTL (s)"><input className="input w-full" type="number" value={s.cache_max_ttl_seconds} onChange={e => patch({ cache_max_ttl_seconds: Number(e.target.value) })} /></Field>
        </div>
        <div className="flex items-center justify-between">
          <div className="text-xs text-zinc-500">{status.cache.entries} entries · {status.cache_hit_rate.toFixed(1)}% hit rate · {status.cache.evictions} evictions</div>
          <button className="btn-ghost" onClick={async () => { await api.post('/api/v1/cache/flush'); load() }}><RefreshCw className="h-3.5 w-3.5" /> Flush cache</button>
        </div>
      </section>

      <section className="card space-y-4 p-5">
        <h2 className="text-sm font-semibold text-zinc-200">Maintenance</h2>
        <div className="grid grid-cols-2 gap-3">
          <Field label="Blocklist refresh (hours)"><input className="input w-full" type="number" value={s.blocklist_refresh_hours} onChange={e => patch({ blocklist_refresh_hours: Number(e.target.value) })} /></Field>
          <Field label="Query log retention (days)"><input className="input w-full" type="number" value={s.query_retention_days} onChange={e => patch({ query_retention_days: Number(e.target.value) })} /></Field>
        </div>
        {fe('blocklist_refresh_hours')}{fe('query_retention_days')}
        <div className="flex items-center justify-between">
          <div>
            <div className="text-sm text-zinc-300">Parallel upstream queries</div>
            <div className="text-xs text-zinc-500">Race all upstreams instead of trying in priority order. Faster, but every upstream sees your queries.</div>
          </div>
          <Toggle on={s.parallel_upstreams} onChange={v => patch({ parallel_upstreams: v })} />
        </div>
        <div className="flex items-center justify-between">
          <div>
            <div className="text-sm text-zinc-300">Allow local blocklist sources</div>
            <div className="text-xs text-zinc-500">Permit http:// URLs and private-range hosts for blocklists (e.g. a list server on your LAN). Keep off unless you need it.</div>
          </div>
          <Toggle on={s.allow_private_lists} onChange={v => patch({ allow_private_lists: v })} />
        </div>
        <div className="grid grid-cols-2 gap-3">
          <Field label="Health-check domain"><input className="input w-full font-mono" value={s.health_probe_domain} onChange={e => patch({ health_probe_domain: e.target.value })} /></Field>
          <Field label="Health interval (s)"><input className="input w-full" type="number" value={s.health_probe_interval_seconds} onChange={e => patch({ health_probe_interval_seconds: Number(e.target.value) })} /></Field>
        </div>
      </section>

      <section className="card space-y-3 p-5">
        <h2 className="text-sm font-semibold text-zinc-200">Backup & restore</h2>
        <p className="text-xs text-zinc-500">Backups contain settings, custom rules, blocklist sources, client aliases and upstreams.</p>
        <div className="flex flex-wrap gap-2">
          <button className="btn-ghost" onClick={() => doBackup(false)}><Download className="h-3.5 w-3.5" /> Backup</button>
          <button className="btn-ghost" onClick={() => doBackup(true)}><Download className="h-3.5 w-3.5" /> Backup + query history</button>
          <button className="btn-ghost" onClick={() => fileRef.current?.click()}><Upload className="h-3.5 w-3.5" /> Restore…</button>
          <input ref={fileRef} type="file" accept=".zip" className="hidden" onChange={e => { const f = e.target.files?.[0]; if (f) restore(f); e.target.value = '' }} />
        </div>
      </section>

      <section className="card space-y-2 p-5">
        <h2 className="text-sm font-semibold text-zinc-200">Network listeners</h2>
        <p className="text-xs text-zinc-500">
          DNS listen addresses, trusted client ranges and the dashboard bind are set in{' '}
          <code className="font-mono text-zinc-400">config.yaml</code> and require a restart.
        </p>
        <div className="text-xs text-zinc-400 font-mono">DNS: {status.dns_listeners.join(', ')}</div>
        <div className="text-xs text-zinc-400 font-mono">Trusted: {status.trusted_cidrs.join(', ')}</div>
      </section>

      <section className="card p-5 text-xs text-zinc-500">
        <span>Version {status.version} — see <a className="text-violet-400 hover:underline" href="/about">About</a>.</span>
      </section>
    </div>
  )
}
