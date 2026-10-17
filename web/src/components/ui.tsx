import { Component, ReactNode } from 'react'
import { AlertTriangle, Inbox, Loader2 } from 'lucide-react'

// ErrorBoundary keeps a single page's render crash from taking down the
// whole dashboard — shows the error and a retry instead of a blank screen.
export class ErrorBoundary extends Component<{ children: ReactNode }, { error: Error | null }> {
  state = { error: null as Error | null }
  static getDerivedStateFromError(error: Error) { return { error } }
  render() {
    if (this.state.error) {
      return (
        <div className="card mx-auto mt-10 max-w-lg p-6 text-center">
          <AlertTriangle className="mx-auto h-5 w-5 text-red-400" />
          <div className="mt-2 text-sm font-medium text-red-300">This page failed to render</div>
          <div className="mt-1 font-mono text-xs text-zinc-500">{this.state.error.message}</div>
          <button className="btn-ghost mt-3" onClick={() => this.setState({ error: null })}>Retry</button>
        </div>
      )
    }
    return this.props.children
  }
}

// PageHeader — consistent page title row: title, optional description, actions.
export function PageHeader({ title, desc, children }: { title: string; desc?: string; children?: ReactNode }) {
  return (
    <div className="flex flex-wrap items-end justify-between gap-3">
      <div>
        <h1 className="page-title">{title}</h1>
        {desc && <p className="page-sub">{desc}</p>}
      </div>
      {children && <div className="flex items-center gap-2">{children}</div>}
    </div>
  )
}

// SectionLabel — small uppercase label above card sections.
export function SectionLabel({ children }: { children: ReactNode }) {
  return (
    <div className="mb-2 text-[11px] font-semibold uppercase tracking-[0.08em] text-zinc-500">{children}</div>
  )
}

export function StatCard({ label, value, sub, accent, icon }: {
  label: string; value: ReactNode; sub?: ReactNode; accent?: boolean; icon?: ReactNode
}) {
  return (
    <div className="card card-hover px-4 py-3">
      <div className="flex items-center justify-between">
        <div className="text-[11px] font-medium uppercase tracking-[0.08em] text-zinc-500">{label}</div>
        {icon && <span className="text-zinc-600">{icon}</span>}
      </div>
      <div className={`mt-1.5 text-2xl font-semibold tracking-tight tabular-nums ${accent ? 'text-violet-300' : 'text-zinc-50'}`}>{value}</div>
      {sub && <div className="mt-0.5 text-xs text-zinc-500">{sub}</div>}
    </div>
  )
}

export function Badge({ tone, children }: { tone: 'ok' | 'bad' | 'warn' | 'muted' | 'accent'; children: ReactNode }) {
  const cls = {
    ok: 'bg-emerald-500/10 text-emerald-300 border-emerald-500/25',
    bad: 'bg-red-500/10 text-red-300 border-red-500/25',
    warn: 'bg-amber-500/10 text-amber-300 border-amber-500/25',
    muted: 'bg-zinc-500/10 text-zinc-400 border-zinc-500/25',
    accent: 'bg-violet-500/12 text-violet-300 border-violet-500/30',
  }[tone]
  return <span className={`inline-flex items-center rounded-md border px-1.5 py-0.5 text-[11px] font-medium leading-4 ${cls}`}>{children}</span>
}

// StatusDot — colored pulse dot for live status indicators.
export function StatusDot({ tone }: { tone: 'ok' | 'bad' | 'warn' | 'muted' }) {
  const c = { ok: 'bg-emerald-400', bad: 'bg-red-400', warn: 'bg-amber-400', muted: 'bg-zinc-500' }[tone]
  return <span className={`inline-block h-1.5 w-1.5 rounded-full ${c} ${tone !== 'muted' ? 'shadow-[0_0_6px_1px_currentColor]' : ''}`} />
}

export function Toggle({ on, onChange, disabled }: { on: boolean; onChange: (v: boolean) => void; disabled?: boolean }) {
  return (
    <button
      type="button"
      disabled={disabled}
      onClick={() => onChange(!on)}
      className={`inline-flex h-5 w-9 shrink-0 items-center rounded-full px-0.5 transition-colors duration-200 disabled:opacity-40 cursor-pointer
        focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-violet-500/40
        ${on ? 'bg-violet-600' : 'bg-zinc-700'}`}
      aria-pressed={on}
    >
      <span
        className={`h-4 w-4 rounded-full bg-white shadow transition-transform duration-200 ${on ? 'translate-x-4' : 'translate-x-0'}`} />
    </button>
  )
}

export function Modal({ title, onClose, children, wide }: {
  title: string; onClose: () => void; children: ReactNode; wide?: boolean
}) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4 backdrop-blur-sm" onClick={onClose}>
      <div
        className={`card w-full ${wide ? 'max-w-2xl' : 'max-w-md'} border-white/10 bg-zinc-900 shadow-2xl shadow-black/60`}
        onClick={e => e.stopPropagation()}
      >
        <div className="flex items-center justify-between border-b border-white/[0.07] px-4 py-3">
          <h2 className="text-sm font-semibold text-zinc-100">{title}</h2>
          <button onClick={onClose} className="rounded p-0.5 text-zinc-500 transition-colors hover:bg-white/5 hover:text-zinc-200 cursor-pointer text-lg leading-none">&times;</button>
        </div>
        <div className="p-4">{children}</div>
      </div>
    </div>
  )
}

export function EmptyState({ title, hint, icon }: { title: string; hint?: string; icon?: ReactNode }) {
  return (
    <div className="card flex flex-col items-center justify-center py-14 text-center">
      <div className="mb-2 text-zinc-700">{icon ?? <Inbox className="h-7 w-7" />}</div>
      <div className="text-sm font-medium text-zinc-400">{title}</div>
      {hint && <div className="mt-1 max-w-md text-xs leading-relaxed text-zinc-600">{hint}</div>}
    </div>
  )
}

export function ErrorBox({ error }: { error: unknown }) {
  if (!error) return null
  const msg = error instanceof Error ? error.message : String(error)
  return (
    <div className="flex items-center gap-2 rounded-lg border border-red-500/25 bg-red-500/10 px-3 py-2 text-sm text-red-300">
      <AlertTriangle className="h-4 w-4 shrink-0" />
      {msg}
    </div>
  )
}

export function Loading() {
  return (
    <div className="flex items-center justify-center gap-2 py-14 text-sm text-zinc-500">
      <Loader2 className="h-4 w-4 animate-spin" /> Loading…
    </div>
  )
}

// Shared dark chart theme for recharts — tooltips default to black text.
export const chartTooltip = {
  contentStyle: {
    background: '#131316',
    border: '1px solid rgba(255,255,255,0.09)',
    borderRadius: 10,
    fontSize: 12,
    color: '#e4e4e7',
    boxShadow: '0 4px 16px rgba(0,0,0,0.5)',
  },
  labelStyle: { color: '#e4e4e7' },
  itemStyle: { color: '#d4d4d8' },
} as const

export const chartLegend = { fontSize: 11, color: '#a1a1a5' } as const

// RankList — horizontal bar ranking used by Overview/Analytics: rank, name,
// proportional bar, and always-visible count. More readable than tiny chart
// axes and can't clip labels.
export function RankList({ items, barColor, showAlias, empty }: {
  items: { value: string; total: number; alias?: string }[]
  barColor: string
  showAlias?: boolean
  empty: string
}) {
  const max = Math.max(1, ...items.map(i => i.total))
  if (items.length === 0) {
    return <div className="py-8 text-center text-xs text-zinc-600">{empty}</div>
  }
  return (
    <div>
      {items.map((it, i) => {
        const name = (showAlias && it.alias) || it.value
        return (
          <div key={`${name}-${i}`} className="flex items-center gap-2.5 py-[5px]" title={it.alias ? `${name} (${it.value})` : name}>
            <span className="w-4 shrink-0 text-right text-[11px] tabular-nums text-zinc-600">{i + 1}</span>
            <span className="min-w-0 flex-1 truncate font-mono text-xs text-zinc-300">{name}</span>
            <div className="h-1.5 w-20 shrink-0 overflow-hidden rounded-full bg-white/[0.06] sm:w-24">
              <div className="h-full rounded-full" style={{ width: `${(it.total / max) * 100}%`, background: barColor, opacity: 0.8 }} />
            </div>
            <span className="w-14 shrink-0 text-right font-mono text-xs tabular-nums text-zinc-400">{it.total.toLocaleString()}</span>
          </div>
        )
      })}
    </div>
  )
}

export function Field({ label, children, hint }: { label: string; children: ReactNode; hint?: string }) {
  return (
    <label className="block">
      <span className="mb-1 block text-xs font-medium text-zinc-400">{label}</span>
      {children}
      {hint && <span className="mt-1 block text-xs text-zinc-600">{hint}</span>}
    </label>
  )
}
