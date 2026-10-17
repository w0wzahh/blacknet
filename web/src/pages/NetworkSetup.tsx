import { useEffect, useState } from 'react'
import { Copy, CheckCircle2, XCircle, RefreshCw, FlaskConical } from 'lucide-react'
import { api, fmtTime } from '../lib/api'
import { NetInterface, NetworkInfo, Diagnostics } from '../lib/types'
import { Badge, ErrorBox, Loading } from '../components/ui'

export function NetworkSetup() {
  const [ifs, setIfs] = useState<NetInterface[] | null>(null)
  const [info, setInfo] = useState<NetworkInfo | null>(null)
  const [diag, setDiag] = useState<Diagnostics | null>(null)
  const [testDomain, setTestDomain] = useState('ads.example.com')
  const [err, setErr] = useState<unknown>(null)
  const [copied, setCopied] = useState('')

  const load = async () => {
    try {
      const [i, n] = await Promise.all([
        api.get<NetInterface[]>('/api/v1/network/interfaces'),
        api.get<NetworkInfo>('/api/v1/network/info'),
      ])
      setIfs(i); setInfo(n); setErr(null)
    } catch (e) { setErr(e) }
  }
  useEffect(() => { load() }, [])

  const runDiag = async () => {
    setDiag(await api.get<Diagnostics>(`/api/v1/diagnostics?domain=${encodeURIComponent(testDomain)}`))
  }

  const copy = (text: string) => {
    navigator.clipboard.writeText(text)
    setCopied(text); setTimeout(() => setCopied(''), 1500)
  }

  if (!ifs || !info) return <Loading />
  const dnsAddr = info.primary_ipv4 ? `${info.primary_ipv4}` : 'this server'

  return (
    <div className="space-y-5">
      <h1 className="text-lg font-semibold text-zinc-100">Network Setup</h1>
      <ErrorBox error={err} />

      <section className="card p-5 space-y-3">
        <h2 className="text-sm font-semibold text-zinc-200">How Blacknet protects your network</h2>
        <p className="text-sm text-zinc-400 leading-relaxed">
          Blacknet is a DNS resolver. Devices and routers don't get "filtered" by installing something —
          they must <em>use Blacknet as their DNS server</em>. Once your router advertises Blacknet's
          address as the network DNS, every device that accepts it gets filtered automatically.
        </p>
      </section>

      <section className="card p-5 space-y-4">
        <h2 className="text-sm font-semibold text-zinc-200">Step 1 — Give this host a stable address</h2>
        <p className="text-sm text-zinc-400">
          Your network needs Blacknet to stay at a fixed IP. The detected LAN address is:
        </p>
        <div className="flex items-center gap-2">
          <code className="rounded bg-zinc-950 px-3 py-1.5 font-mono text-sm text-violet-300">{info.primary_ipv4 || 'not detected'}</code>
          <button className="btn-ghost !px-2" onClick={() => copy(info.primary_ipv4)}>
            {copied === info.primary_ipv4 ? <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" /> : <Copy className="h-3.5 w-3.5" />}
          </button>
        </div>
        <p className="text-xs text-zinc-500">
          In your router, create a <strong>DHCP reservation</strong> for this machine's MAC address, or
          configure a static IP outside the DHCP pool. Skipping this means the DNS address can change and break resolution.
        </p>
      </section>

      <section className="card p-5 space-y-4">
        <h2 className="text-sm font-semibold text-zinc-200">Step 2 — Point your router's DNS at Blacknet</h2>
        <ol className="list-decimal space-y-2 pl-5 text-sm text-zinc-400">
          <li>Open your router's admin page (often <code className="font-mono text-zinc-300">{info.gateway_guess || '192.168.x.1'}</code>).</li>
          <li>Find <strong>DHCP</strong> or <strong>LAN</strong> settings — look for "DNS server" fields.</li>
          <li>Set the primary DNS to <code className="font-mono text-violet-300">{info.primary_ipv4 || '<this host>'}</code>. Remove or leave the secondary empty (a secondary public DNS lets devices bypass filtering).</li>
          <li>Save. Devices pick up the new DNS on their next DHCP lease — renew or reboot to speed it up.</li>
        </ol>
        <p className="text-xs text-zinc-500">
          Router interfaces vary: look under Internet/WAN → DNS, or LAN → DHCP Server → DNS. If the router won't
          let you set a LAN DNS, you can instead disable its DHCP entirely and run Blacknet's optional DHCP mode —
          or configure devices individually.
        </p>
        <div className="rounded-md border border-zinc-800 bg-zinc-950/50 p-3 text-xs text-zinc-500">
          <strong className="text-zinc-400">Recovery:</strong> if anything breaks, set the router's DNS back to
          "automatic" / your ISP defaults (e.g. {info.gateway_guess || '192.168.x.1'}) and renew DHCP leases.
        </div>
      </section>

      <section className="card p-5 space-y-4">
        <h2 className="text-sm font-semibold text-zinc-200">Step 3 — Verify filtering works</h2>
        <p className="text-sm text-zinc-400">
          From another device on the network run{' '}
          <code className="font-mono text-zinc-300">nslookup ads.example.com {info.primary_ipv4}</code>{' '}
          or use the check below (tests the engine rules, not a specific device).
        </p>
        <div className="flex gap-2">
          <input className="input w-64 font-mono" value={testDomain} onChange={e => setTestDomain(e.target.value)} placeholder="domain to test" />
          <button className="btn-primary" onClick={runDiag}><FlaskConical className="h-3.5 w-3.5" /> Run diagnostics</button>
        </div>
        {diag && (
          <div className="grid gap-2 rounded-md border border-zinc-800 bg-zinc-950/50 p-3 text-sm sm:grid-cols-2">
            <Row k="DNS service" v={<Badge tone="ok">{diag.dns_service}</Badge>} />
            <Row k="Database" v={diag.db_ok ? <Badge tone="ok">ok</Badge> : <Badge tone="bad">error</Badge>} />
            <Row k={`"${diag.test_domain}"`} v={diag.test_decision.blocked ? <Badge tone="bad">blocked</Badge> : <Badge tone="ok">allowed</Badge>} />
            <Row k="Decision reason" v={<span className="text-zinc-400">{diag.test_decision.reason}</span>} />
            <Row k="Upstreams healthy" v={<span className="text-zinc-400">{diag.upstreams_healthy}/{diag.upstreams_total}</span>} />
            <Row k="You appear as" v={<span className="font-mono text-zinc-400">{diag.caller_ip}{diag.caller_known ? ' (known client)' : ' (not yet seen)'}</span>} />
          </div>
        )}
      </section>

      <section className="card p-5 space-y-3">
        <h2 className="text-sm font-semibold text-zinc-200">Interfaces & listeners</h2>
        <table className="w-full">
          <thead><tr><th className="th">Interface</th><th className="th">Addresses</th><th className="th">State</th></tr></thead>
          <tbody>
            {ifs.filter(i => i.is_up).map(i => (
              <tr key={i.name}>
                <td className="td text-xs">{i.name}{i.is_loopback && <span className="ml-1 text-zinc-600">(loopback)</span>}</td>
                <td className="td font-mono text-xs">{i.addrs.join(', ')}</td>
                <td className="td">{i.is_up ? <Badge tone="ok">up</Badge> : <Badge tone="muted">down</Badge>}</td>
              </tr>
            ))}
          </tbody>
        </table>
        <div className="text-xs text-zinc-500 space-y-1">
          <div>DNS listening on: <code className="font-mono text-zinc-400">{info.dns_listen.join(', ')}</code> (change in config.yaml, restart required)</div>
          <div>Trusted client networks: <code className="font-mono text-zinc-400">{info.trusted_cidrs.join(', ')}</code></div>
          <div className="text-zinc-600">Queries from outside these ranges are refused — the resolver is never open to the public internet by default.</div>
        </div>
      </section>

      <section className="card p-5 space-y-4">
        <h2 className="text-sm font-semibold text-zinc-200">Advanced: Blacknet-managed DHCP <Badge tone="warn">experimental</Badge></h2>
        <p className="text-xs text-zinc-500 leading-relaxed">
          If your router can't change its advertised DNS, Blacknet can serve DHCP itself — assigning
          addresses <em>and</em> its own DNS. This requires disabling your router's DHCP first; two
          DHCP servers on one LAN conflict. Disabled by default.
        </p>
        <DHCPPanel primaryIPv4={info.primary_ipv4} gateway={info.gateway_guess} />
      </section>

      <section className="card p-5 space-y-3">
        <h2 className="text-sm font-semibold text-zinc-200">Limitations — honest expectations</h2>
        <ul className="list-disc space-y-1.5 pl-5 text-xs text-zinc-500 leading-relaxed">
          <li>DNS filtering blocks whole domains. Ads served from the same domain as content (e.g. YouTube, Instagram) cannot be blocked this way.</li>
          <li>Devices with hard-coded DNS, their own DoH/DoT, or a VPN can bypass Blacknet. DNS logs alone can't prove a device isn't bypassing.</li>
          <li>To catch bypasses you'd need router-level firewall rules blocking outbound port 53/853 to other servers — advanced and router-dependent.</li>
          <li>Encrypted client DNS (DoH inside browsers/apps) is invisible to any network DNS filter.</li>
        </ul>
      </section>
    </div>
  )
}

function Row({ k, v }: { k: string; v: React.ReactNode }) {
  return (
    <div className="flex items-center justify-between gap-2">
      <span className="text-zinc-500 text-xs">{k}</span>
      <span>{v}</span>
    </div>
  )
}

interface DHCPConfig {
  enabled: boolean
  interface_ip: string
  pool_start: string
  pool_end: string
  mask: string
  gateway: string
  lease_seconds: number
}
interface DHCPLease { mac: string; ip: string; hostname?: string; expires_at: string }

function DHCPPanel({ primaryIPv4, gateway }: { primaryIPv4: string; gateway: string }) {
  const [cfg, setCfg] = useState<DHCPConfig | null>(null)
  const [running, setRunning] = useState(false)
  const [leases, setLeases] = useState<DHCPLease[]>([])
  const [err, setErr] = useState('')
  const [fields, setFields] = useState<Record<string, string>>({})
  const [ack, setAck] = useState(false)
  const [detected, setDetected] = useState<boolean | null>(null)

  const load = () => api.get<{ config: DHCPConfig; running: boolean; leases: DHCPLease[] }>('/api/v1/dhcp')
    .then(r => {
      setCfg(r.config?.interface_ip ? r.config : {
        enabled: false, interface_ip: primaryIPv4, pool_start: '192.168.1.100',
        pool_end: '192.168.1.200', mask: '255.255.255.0', gateway, lease_seconds: 3600,
      })
      setRunning(r.running); setLeases(r.leases || [])
    }).catch(e => setErr(String(e)))

  useEffect(() => { load() }, [])

  const detect = async () => {
    setErr(''); setDetected(null)
    try {
      const r = await api.post<{ other_dhcp_server_detected: boolean }>('/api/v1/dhcp/detect', { interface_ip: cfg?.interface_ip })
      setDetected(r.other_dhcp_server_detected)
    } catch (e) { setErr(e instanceof Error ? e.message : String(e)) }
  }

  const save = async (enabled: boolean) => {
    if (!cfg) return
    setErr(''); setFields({})
    try {
      const res = await fetch('/api/v1/dhcp', {
        method: 'PUT',
        headers: { 'X-Requested-With': 'XMLHttpRequest', 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify({ config: { ...cfg, enabled }, acknowledge_conflict: ack }),
      })
      const data = await res.json()
      if (!res.ok) {
        setErr(data.error || 'rejected')
        if (data.fields) setFields(data.fields)
        return
      }
      setCfg({ ...cfg, enabled }); setAck(false)
      load()
    } catch (e) { setErr(String(e)) }
  }

  if (!cfg) return null
  const F = (k: keyof DHCPConfig, label: string) => (
    <label className="block" key={k}>
      <span className="mb-1 block text-xs text-zinc-500">{label}</span>
      <input className="input w-full font-mono text-xs" value={String(cfg[k])}
        onChange={e => setCfg({ ...cfg, [k]: k === 'lease_seconds' ? Number(e.target.value) : e.target.value })} />
    </label>
  )

  return (
    <div className="space-y-3">
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3">
        {F('interface_ip', 'This host (server) IP')}
        {F('mask', 'Subnet mask')}
        {F('gateway', 'Gateway (router)')}
        {F('pool_start', 'Pool start')}
        {F('pool_end', 'Pool end')}
        {F('lease_seconds', 'Lease seconds')}
      </div>
      {fields.config && <div className="text-xs text-red-400">{fields.config}</div>}
      {fields.conflict && <div className="rounded border border-amber-800/60 bg-amber-950/40 px-3 py-2 text-xs text-amber-300">{fields.conflict}</div>}
      <div className="flex flex-wrap items-center gap-2">
        <button className="btn-ghost" onClick={detect}>Detect other DHCP servers</button>
        {detected === true && <Badge tone="warn">another DHCP server detected</Badge>}
        {detected === false && <Badge tone="ok">none detected</Badge>}
        {(detected || fields.conflict) && !running && (
          <label className="flex items-center gap-1.5 text-xs text-zinc-400">
            <input type="checkbox" checked={ack} onChange={e => setAck(e.target.checked)} />
            I disabled the router's DHCP / accept the risk
          </label>
        )}
        {!running
          ? <button className="btn-primary" onClick={() => save(true)}>Enable DHCP server</button>
          : <button className="btn-danger" onClick={() => save(false)}>Disable DHCP server</button>}
      </div>
      {err && <ErrorBox error={err} />}
      {running && (
        <div>
          <div className="mb-1 text-xs font-medium uppercase tracking-wide text-zinc-500">Active leases</div>
          {leases.length === 0
            ? <div className="text-xs text-zinc-600">No leases yet</div>
            : (
              <table className="w-full">
                <thead><tr><th className="th">MAC</th><th className="th">IP</th><th className="th">Hostname</th><th className="th">Expires</th></tr></thead>
                <tbody>
                  {leases.map(l => (
                    <tr key={l.mac}>
                      <td className="td font-mono text-xs">{l.mac}</td>
                      <td className="td font-mono text-xs">{l.ip}</td>
                      <td className="td text-xs">{l.hostname || '—'}</td>
                      <td className="td text-xs text-zinc-500">{fmtTime(l.expires_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
        </div>
      )}
      <p className="text-xs text-zinc-600">
        Rollback: disable here, re-enable the router's DHCP, then renew client leases.
      </p>
    </div>
  )
}
