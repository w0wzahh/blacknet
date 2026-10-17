import { useEffect, useState } from 'react'
import { Github, Globe, Shield, ExternalLink, Heart, Code2 } from 'lucide-react'
import { api } from '../lib/api'
import { Status } from '../lib/types'
import { Loading, PageHeader, SectionLabel, Badge } from '../components/ui'

const LINKS = [
  {
    label: 'GitHub',
    desc: 'github.com/w0wzahh — source, issues and releases',
    href: 'https://github.com/w0wzahh',
    icon: Github,
  },
  {
    label: 'Website',
    desc: 'w0wzahh.link',
    href: 'https://w0wzahh.link',
    icon: Globe,
  },
  {
    label: 'Repository',
    desc: 'github.com/w0wzahh/blacknet — stars and bug reports welcome',
    href: 'https://github.com/w0wzahh/blacknet',
    icon: Code2,
  },
]

const STACK = [
  { name: 'Go', role: 'DNS server, filtering engine, API' },
  { name: 'React + TypeScript', role: 'dashboard frontend' },
  { name: 'Tailwind CSS', role: 'design system' },
  { name: 'miekg/dns', role: 'DNS wire protocol' },
  { name: 'SQLite (modernc)', role: 'query log and persistence' },
  { name: 'Recharts + lucide', role: 'charts and icons' },
]

export function Credits() {
  const [st, setSt] = useState<Status | null>(null)
  useEffect(() => { api.get<Status>('/api/v1/status').then(setSt).catch(() => {}) }, [])
  if (!st) return <Loading />

  return (
    <div className="max-w-2xl space-y-5">
      <PageHeader title="Credits" desc="Who made this and what it's built on." />

      <div className="card p-5">
        <div className="flex items-center gap-4">
          <div className="flex h-12 w-12 shrink-0 items-center justify-center rounded-xl bg-violet-600/20 text-violet-400">
            <Shield className="h-6 w-6" strokeWidth={1.75} />
          </div>
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-base font-semibold tracking-tight text-zinc-50">Blacknet</span>
              <Badge tone="accent">v{st.version}</Badge>
              <Badge tone="muted">MIT License</Badge>
            </div>
            <p className="mt-0.5 text-xs text-zinc-500">
              Self-hosted, network-wide DNS ad and tracker blocker — designed and built by w0wzahh.
            </p>
          </div>
        </div>
      </div>

      <div>
        <SectionLabel>Author</SectionLabel>
        <div className="card divide-y divide-white/[0.05]">
          {LINKS.map(l => (
            <a
              key={l.label}
              href={l.href}
              target="_blank"
              rel="noreferrer"
              className="group flex items-center gap-3 px-4 py-3 transition-colors hover:bg-white/[0.03]"
            >
              <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg border border-white/[0.07] bg-white/[0.03] text-zinc-400 transition-colors group-hover:border-violet-500/30 group-hover:text-violet-300">
                <l.icon className="h-4 w-4" strokeWidth={1.75} />
              </div>
              <div className="min-w-0 flex-1">
                <div className="text-sm font-medium text-zinc-200 transition-colors group-hover:text-zinc-50">{l.label}</div>
                <div className="truncate text-xs text-zinc-500">{l.desc}</div>
              </div>
              <ExternalLink className="h-3.5 w-3.5 shrink-0 text-zinc-600 transition-colors group-hover:text-zinc-400" />
            </a>
          ))}
        </div>
      </div>

      <div>
        <SectionLabel>Built with</SectionLabel>
        <div className="card divide-y divide-white/[0.05]">
          {STACK.map(s => (
            <div key={s.name} className="flex items-center justify-between gap-3 px-4 py-2.5">
              <span className="text-sm text-zinc-300">{s.name}</span>
              <span className="text-xs text-zinc-600">{s.role}</span>
            </div>
          ))}
        </div>
      </div>

      <div className="card p-5 text-xs leading-relaxed text-zinc-500">
        <p className="flex items-center gap-1.5 text-zinc-400">
          <Heart className="h-3.5 w-3.5 text-violet-400" />
          Thanks for running Blacknet.
        </p>
        <p className="mt-2">
          Blacknet runs entirely on your hardware — no account, no cloud service, no telemetry.
          Inspired by the operational model of Pi-hole and AdGuard Home, with an original
          codebase and interface.
        </p>
      </div>
    </div>
  )
}
