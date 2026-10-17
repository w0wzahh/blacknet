import { useEffect, useState } from 'react'
import { Shield, CheckCircle2, XCircle, ArrowRight, ArrowLeft } from 'lucide-react'
import { api } from '../lib/api'
import { NetworkInfo, Diagnostics, Status } from '../lib/types'
import { Badge, ErrorBox } from '../components/ui'

const STEPS = ['Welcome', 'Deployment', 'Network', 'DNS config', 'Protection', 'Admin', 'Validate', 'Router', 'Verify']

export function SetupWizard({ onDone }: { onDone: () => void }) {
  const [step, setStep] = useState(0)
  const [netInfo, setNetInfo] = useState<NetworkInfo | null>(null)
  const [status, setStatus] = useState<Status | null>(null)
  const [password, setPassword] = useState('')
  const [password2, setPassword2] = useState('')
  const [pwErr, setPwErr] = useState('')
  const [pwSet, setPwSet] = useState(false)
  const [diag, setDiag] = useState<Diagnostics | null>(null)
  const [err, setErr] = useState('')

  // Wizard must be restart-safe: network info loads on demand, nothing is
  // persisted until the admin step writes the password and the last step
  // marks setup complete.
  useEffect(() => {
    api.get<Status>('/api/v1/status').then(setStatus).catch(() => {})
    api.get<NetworkInfo>('/api/v1/network/info').then(setNetInfo).catch(() => {})
  }, [])

  const setPw = async () => {
    setPwErr('')
    if (password.length < 8) { setPwErr('Password needs at least 8 characters.'); return }
    if (password !== password2) { setPwErr('Passwords do not match.'); return }
    try {
      await api.post('/api/v1/setup/password', { password })
      setPwSet(true)
      setStep(s => s + 1)
    } catch (e) { setPwErr(e instanceof Error ? e.message : 'failed') }
  }

  const finish = async () => {
    try {
      await api.patch('/api/v1/settings', { setup_completed: true })
    } catch { /* still complete */ }
    onDone()
  }

  const runDiag = async () => {
    try { setDiag(await api.get<Diagnostics>('/api/v1/diagnostics?domain=doubleclick.net')) }
    catch (e) { setErr(e instanceof Error ? e.message : 'diagnostics failed') }
  }

  const next = () => setStep(s => Math.min(s + 1, STEPS.length - 1))
  const back = () => setStep(s => Math.max(s - 1, 0))

  return (
    <div className="flex h-full items-center justify-center bg-zinc-950 p-6">
      <div className="card w-full max-w-2xl">
        <div className="flex items-center gap-2 border-b border-zinc-800 px-6 py-4">
          <Shield className="h-5 w-5 text-violet-400" />
          <span className="font-semibold">Blacknet setup</span>
          <span className="ml-auto text-xs text-zinc-500">{STEPS[step]} — step {step + 1}/{STEPS.length}</span>
        </div>
        <div className="px-6 py-5 min-h-[320px]">
          {step === 0 && (
            <div className="space-y-3 text-sm text-zinc-400 leading-relaxed">
              <h2 className="text-base font-semibold text-zinc-100">Welcome</h2>
              <p>Blacknet is a self-hosted DNS server that blocks ads, trackers and malicious domains for every device that uses it.</p>
              <p>You need: this computer (always on, wired to your router is best), and access to your router's settings to change the network DNS.</p>
              <p className="text-xs text-zinc-600">No account, cloud service or subscription is involved — everything runs and stays on your hardware.</p>
            </div>
          )}
          {step === 1 && (
            <div className="space-y-3 text-sm text-zinc-400 leading-relaxed">
              <h2 className="text-base font-semibold text-zinc-100">Deployment mode</h2>
              <p>You are running the <strong>Windows-hosted</strong> deployment: Blacknet runs on this PC and answers DNS for the LAN. Other supported modes: Linux server, Docker container, and (later) OpenWrt router firmware.</p>
              <ul className="list-disc pl-5 space-y-1 text-xs text-zinc-500">
                <li>Keep this PC on and connected — when it's off, devices can't resolve names.</li>
                <li>Serving DNS on port 53 requires administrator privileges and firewall permission.</li>
              </ul>
            </div>
          )}
          {step === 2 && (
            <div className="space-y-3 text-sm text-zinc-400">
              <h2 className="text-base font-semibold text-zinc-100">Network interface</h2>
              {netInfo ? (
                <>
                  <p>Detected LAN address of this host:</p>
                  <code className="block w-fit rounded bg-zinc-950 px-3 py-2 font-mono text-violet-300">{netInfo.primary_ipv4 || 'not detected'}</code>
                  <p className="text-xs text-zinc-500">Reserve this address in your router (DHCP reservation) or set it statically so it never changes.</p>
                </>
              ) : <p className="text-zinc-600">Detecting interfaces…</p>}
            </div>
          )}
          {step === 3 && (
            <div className="space-y-3 text-sm text-zinc-400">
              <h2 className="text-base font-semibold text-zinc-100">DNS configuration</h2>
              {netInfo && (
                <div className="space-y-2 text-xs">
                  <Row2 k="Listening on" v={netInfo.dns_listen.join(', ')} mono />
                  <Row2 k="Trusted clients" v={netInfo.trusted_cidrs.join(', ')} mono />
                </div>
              )}
              <p className="text-xs text-zinc-500">Edit <code className="font-mono">config.yaml</code> to change listen addresses or trusted ranges, then restart the service.</p>
            </div>
          )}
          {step === 4 && (
            <div className="space-y-3 text-sm text-zinc-400">
              <h2 className="text-base font-semibold text-zinc-100">Protection</h2>
              <p>Two maintained blocklists were seeded and will refresh automatically: StevenBlack Unified Hosts and the AdGuard DNS filter.</p>
              <p>Blocking mode is <strong>NXDOMAIN</strong> — change it later in Settings. Custom allow/block rules always take precedence over lists.</p>
            </div>
          )}
          {step === 5 && (
            <div className="space-y-3">
              <h2 className="text-base font-semibold text-zinc-100">Administration</h2>
              <p className="text-sm text-zinc-400">Set the dashboard password. Anyone on your LAN can reach this UI, so pick something decent.</p>
              <input type="password" className="input w-full" placeholder="Password (min 8 chars)" value={password} onChange={e => setPassword(e.target.value)} />
              <input type="password" className="input w-full" placeholder="Repeat password" value={password2} onChange={e => setPassword2(e.target.value)} />
              {pwErr && <ErrorBox error={pwErr} />}
              {pwSet && <Badge tone="ok">password saved</Badge>}
            </div>
          )}
          {step === 6 && (
            <div className="space-y-3 text-sm text-zinc-400">
              <h2 className="text-base font-semibold text-zinc-100">Validation</h2>
              {status ? (
                <div className="space-y-2 text-xs">
                  <Row2 k="DNS listeners" v={status.dns_listeners.join(', ')} mono ok />
                  <Row2 k="Upstreams configured" v={`${status.upstreams_total}`} ok={status.upstreams_total > 0} />
                  <Row2 k="Blocklists" v={`${status.active_blocklists} active, ${status.blocklist_domains} domains`} ok />
                  <Row2 k="Password set" v={pwSet ? 'yes' : 'go back to step 6'} ok={pwSet} warn={!pwSet} />
                </div>
              ) : <p>Checking…</p>}
              <p className="text-xs text-zinc-500">Upstream connectivity is tested live on the Upstream DNS page after setup.</p>
            </div>
          )}
          {step === 7 && (
            <div className="space-y-3 text-sm text-zinc-400 leading-relaxed">
              <h2 className="text-base font-semibold text-zinc-100">Router integration</h2>
              <ol className="list-decimal space-y-1.5 pl-5">
                <li>Reserve <code className="font-mono text-violet-300">{netInfo?.primary_ipv4 || 'this host IP'}</code> for this machine in the router's DHCP settings.</li>
                <li>Set the router's advertised DNS server (LAN/DHCP section) to that same address.</li>
                <li>Renew DHCP leases or reboot devices so they pick it up.</li>
                <li>To undo: restore the router's previous DNS setting.</li>
              </ol>
              <p className="text-xs text-zinc-500">The Network Setup page has detailed instructions and live diagnostics.</p>
            </div>
          )}
          {step === 8 && (
            <div className="space-y-3 text-sm text-zinc-400">
              <h2 className="text-base font-semibold text-zinc-100">Verify</h2>
              <p>Run a live check that exercises the rule engine against <code className="font-mono">doubleclick.net</code> (in the default lists once refreshed).</p>
              <button className="btn-ghost" onClick={runDiag}>Run check</button>
              {diag && (
                <div className="space-y-1 rounded-md border border-zinc-800 bg-zinc-950/50 p-3 text-xs">
                  <Row2 k="DNS service" v={diag.dns_service} ok />
                  <Row2 k="Decision" v={diag.test_decision.blocked ? `blocked — ${diag.test_decision.reason}` : `allowed — ${diag.test_decision.reason}`} ok={diag.test_decision.blocked} warn={!diag.test_decision.blocked} />
                  <Row2 k="Upstreams healthy" v={`${diag.upstreams_healthy}/${diag.upstreams_total}`} ok={diag.upstreams_healthy > 0} warn={diag.upstreams_healthy === 0} />
                </div>
              )}
              {err && <ErrorBox error={err} />}
              <p className="text-xs text-zinc-500">Blocklists download in the background; if doubleclick.net isn't blocked yet, lists may still be importing.</p>
            </div>
          )}
        </div>
        <div className="flex items-center justify-between border-t border-zinc-800 px-6 py-4">
          <button className="btn-ghost" disabled={step === 0} onClick={back}><ArrowLeft className="h-3.5 w-3.5" /> Back</button>
          {step === 5 ? (
            <button className="btn-primary" onClick={setPw}>Set password <ArrowRight className="h-3.5 w-3.5" /></button>
          ) : step === STEPS.length - 1 ? (
            <button className="btn-primary" onClick={finish} disabled={!pwSet}>Finish setup</button>
          ) : (
            <button className="btn-primary" onClick={next}>Next <ArrowRight className="h-3.5 w-3.5" /></button>
          )}
        </div>
      </div>
    </div>
  )
}

function Row2({ k, v, mono, ok, warn }: { k: string; v: string; mono?: boolean; ok?: boolean; warn?: boolean }) {
  return (
    <div className="flex items-center justify-between gap-3">
      <span className="text-zinc-500">{k}</span>
      <span className={`flex items-center gap-1.5 ${mono ? 'font-mono' : ''} ${warn ? 'text-amber-400' : 'text-zinc-300'}`}>
        {ok !== undefined && (ok ? <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" /> : <XCircle className="h-3.5 w-3.5 text-red-400" />)}
        {v}
      </span>
    </div>
  )
}
