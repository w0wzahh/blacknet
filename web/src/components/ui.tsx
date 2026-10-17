import { ReactNode } from 'react'

export function StatCard({ label, value, sub, accent }: {
  label: string; value: ReactNode; sub?: ReactNode; accent?: boolean
}) {
  return (
    <div className="card px-4 py-3">
      <div className="text-xs uppercase tracking-wide text-zinc-500">{label}</div>
      <div className={`mt-1 text-2xl font-semibold ${accent ? 'text-violet-400' : 'text-zinc-100'}`}>{value}</div>
      {sub && <div className="mt-0.5 text-xs text-zinc-500">{sub}</div>}
    </div>
  )
}

export function Badge({ tone, children }: { tone: 'ok' | 'bad' | 'warn' | 'muted' | 'accent'; children: ReactNode }) {
  const cls = {
    ok: 'bg-emerald-950/60 text-emerald-400 border-emerald-800/60',
    bad: 'bg-red-950/60 text-red-400 border-red-800/60',
    warn: 'bg-amber-950/60 text-amber-400 border-amber-800/60',
    muted: 'bg-zinc-800/60 text-zinc-400 border-zinc-700',
    accent: 'bg-violet-950/60 text-violet-300 border-violet-800/60',
  }[tone]
  return <span className={`inline-flex items-center rounded border px-1.5 py-0.5 text-xs font-medium ${cls}`}>{children}</span>
}

export function Toggle({ on, onChange, disabled }: { on: boolean; onChange: (v: boolean) => void; disabled?: boolean }) {
  return (
    <button
      type="button"
      disabled={disabled}
      onClick={() => onChange(!on)}
      className={`relative h-5 w-9 rounded-full transition-colors disabled:opacity-40 cursor-pointer
        ${on ? 'bg-violet-600' : 'bg-zinc-700'}`}
      aria-pressed={on}
    >
      <span
        className="absolute left-0 top-0.5 h-4 w-4 rounded-full bg-white transition-transform"
        style={{ transform: on ? 'translateX(18px)' : 'translateX(2px)' }} />
    </button>
  )
}

export function Modal({ title, onClose, children, wide }: {
  title: string; onClose: () => void; children: ReactNode; wide?: boolean
}) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4" onClick={onClose}>
      <div
        className={`card w-full ${wide ? 'max-w-2xl' : 'max-w-md'} bg-zinc-900 shadow-xl`}
        onClick={e => e.stopPropagation()}
      >
        <div className="flex items-center justify-between border-b border-zinc-800 px-4 py-3">
          <h2 className="text-sm font-semibold text-zinc-100">{title}</h2>
          <button onClick={onClose} className="text-zinc-500 hover:text-zinc-300 cursor-pointer text-lg leading-none">&times;</button>
        </div>
        <div className="p-4">{children}</div>
      </div>
    </div>
  )
}

export function EmptyState({ title, hint }: { title: string; hint?: string }) {
  return (
    <div className="card flex flex-col items-center justify-center py-12 text-center">
      <div className="text-sm text-zinc-400">{title}</div>
      {hint && <div className="mt-1 text-xs text-zinc-600">{hint}</div>}
    </div>
  )
}

export function ErrorBox({ error }: { error: unknown }) {
  if (!error) return null
  const msg = error instanceof Error ? error.message : String(error)
  return <div className="rounded-md border border-red-800/60 bg-red-950/40 px-3 py-2 text-sm text-red-300">{msg}</div>
}

export function Loading() {
  return <div className="py-12 text-center text-sm text-zinc-500">Loading…</div>
}

// Shared dark chart theme for recharts — tooltips default to black text.
export const chartTooltip = {
  contentStyle: {
    background: '#18181b',
    border: '1px solid #3f3f46',
    borderRadius: 8,
    fontSize: 12,
    color: '#e4e4e7',
  },
  labelStyle: { color: '#e4e4e7' },
  itemStyle: { color: '#d4d4d8' },
} as const

export const chartLegend = { fontSize: 11, color: '#a1a1a5' } as const

export function Field({ label, children, hint }: { label: string; children: ReactNode; hint?: string }) {
  return (
    <label className="block">
      <span className="mb-1 block text-xs font-medium text-zinc-400">{label}</span>
      {children}
      {hint && <span className="mt-1 block text-xs text-zinc-600">{hint}</span>}
    </label>
  )
}
