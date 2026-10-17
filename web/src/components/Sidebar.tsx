import { NavLink } from 'react-router-dom'
import {
  LayoutDashboard, ScrollText, MonitorSmartphone, ListFilter, ShieldCheck,
  ArrowUpCircle, Network, BarChart3, Settings, Info, Shield,
} from 'lucide-react'

const items = [
  { to: '/', label: 'Overview', icon: LayoutDashboard, end: true },
  { to: '/queries', label: 'Query Log', icon: ScrollText },
  { to: '/clients', label: 'Clients', icon: MonitorSmartphone },
  { to: '/blocklists', label: 'Blocklists', icon: ListFilter },
  { to: '/rules', label: 'Custom Rules', icon: ShieldCheck },
  { to: '/upstreams', label: 'Upstream DNS', icon: ArrowUpCircle },
  { to: '/network', label: 'Network Setup', icon: Network },
  { to: '/analytics', label: 'Analytics', icon: BarChart3 },
  { to: '/settings', label: 'Settings', icon: Settings },
  { to: '/about', label: 'About', icon: Info },
]

export function Sidebar({ version }: { version: string }) {
  return (
    <aside className="flex w-52 shrink-0 flex-col border-r border-zinc-800 bg-zinc-925 bg-zinc-900/40">
      <div className="flex items-center gap-2 px-4 py-4 border-b border-zinc-800">
        <Shield className="h-5 w-5 text-violet-400" strokeWidth={1.75} />
        <span className="text-sm font-semibold tracking-wide text-zinc-100">Blacknet</span>
      </div>
      <nav className="flex-1 overflow-y-auto py-2">
        {items.map(({ to, label, icon: Icon, end }) => (
          <NavLink
            key={to}
            to={to}
            end={end}
            className={({ isActive }) =>
              `flex items-center gap-2.5 px-4 py-2 text-sm transition-colors ${
                isActive
                  ? 'bg-violet-950/40 text-violet-300 border-r-2 border-violet-500'
                  : 'text-zinc-400 hover:bg-zinc-800/60 hover:text-zinc-200'
              }`
            }
          >
            <Icon className="h-4 w-4" strokeWidth={1.75} />
            {label}
          </NavLink>
        ))}
      </nav>
      <div className="border-t border-zinc-800 px-4 py-3 text-xs text-zinc-600">
        <div>Blacknet v{version}</div>
        <div className="mt-0.5">Self-hosted DNS filtering</div>
      </div>
    </aside>
  )
}
