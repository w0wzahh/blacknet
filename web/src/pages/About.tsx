import { useEffect, useState } from 'react'
import { api } from '../lib/api'
import { Status } from '../lib/types'
import { Loading, PageHeader } from '../components/ui'

export function About() {
  const [st, setSt] = useState<Status | null>(null)
  useEffect(() => { api.get<Status>('/api/v1/status').then(setSt).catch(() => {}) }, [])
  if (!st) return <Loading />
  return (
    <div className="max-w-2xl space-y-5">
      <PageHeader title="About" desc="Version, deployment info and useful links." />
      <div className="card space-y-3 p-5">
        <div className="flex items-baseline gap-3">
          <span className="text-xl font-semibold text-zinc-100">Blacknet</span>
          <span className="text-sm text-zinc-500">v{st.version}</span>
        </div>
        <p className="text-sm text-zinc-400 leading-relaxed">
          A self-hosted, network-wide DNS ad and tracker blocker. Blacknet answers DNS queries for
          your network, refuses lookups for advertising, tracking and malicious domains, and forwards
          everything else to your chosen upstream resolvers.
        </p>
        <table className="w-full text-sm">
          <tbody>
            <Row k="Version" v={st.version} />
            <Row k="License" v="MIT" />
            <Row k="DNS listeners" v={st.dns_listeners.join(', ')} />
            <Row k="Trusted ranges" v={st.trusted_cidrs.join(', ')} />
          </tbody>
        </table>
      </div>
      <div className="card p-5 text-sm text-zinc-400 space-y-2">
        <p>
          Privacy: Blacknet runs entirely on your hardware. There is no account, no cloud service,
          no telemetry and no external update check unless you explicitly enable one.
        </p>
        <p>
          Made by w0wzahh — see <a className="text-violet-400 hover:underline" href="/credits">Credits</a> for
          links and acknowledgements.
        </p>
      </div>
    </div>
  )
}

function Row({ k, v }: { k: string; v: string }) {
  return (
    <tr>
      <td className="td w-32 text-xs text-zinc-500">{k}</td>
      <td className="td font-mono text-xs">{v || '—'}</td>
    </tr>
  )
}
