import { NavLink } from 'react-router-dom'
import {
  LayoutDashboard, ScrollText, MonitorSmartphone, ListFilter, ShieldCheck,
  ArrowUpCircle, Network, BarChart3, Settings, Info, Shield,
  Users, CalendarClock, Radar, Globe, Router, HeartPulse, FileClock, Heart,
} from 'lucide-react'

const sections = [
  {
    label: 'Monitor',
    items: [
      { to: '/', label: 'Overview', icon: LayoutDashboard, end: true },
      { to: '/queries', label: 'Query Log', icon: ScrollText },
      { to: '/analytics', label: 'Analytics', icon: BarChart3 },
      { to: '/audit', label: 'Audit Log', icon: FileClock },
    ],
  },
  {
    label: 'Filtering',
    items: [
      { to: '/blocklists', label: 'Blocklists', icon: ListFilter },
      { to: '/rules', label: 'Custom Rules', icon: ShieldCheck },
      { to: '/local-dns', label: 'Local DNS', icon: Globe },
      { to: '/schedules', label: 'Schedules', icon: CalendarClock },
    ],
  },
  {
    label: 'Network',
    items: [
      { to: '/clients', label: 'Clients', icon: MonitorSmartphone },
      { to: '/devices', label: 'Discovery', icon: Radar },
      { to: '/policies', label: 'Policies', icon: Users },
      { to: '/upstreams', label: 'Upstream DNS', icon: ArrowUpCircle },
      { to: '/network', label: 'Network Setup', icon: Network },
      { to: '/enforcement', label: 'Enforcement', icon: Router },
    ],
  },
  {
    label: 'System',
    items: [
      { to: '/health', label: 'Health', icon: HeartPulse },
      { to: '/settings', label: 'Settings', icon: Settings },
      { to: '/about', label: 'About', icon: Info },
      { to: '/credits', label: 'Credits', icon: Heart },
    ],
  },
]

export function Sidebar({ version, protectionOn }: { version: string; protectionOn?: boolean }) {
  return (
    <aside className="flex w-60 shrink-0 flex-col border-r border-white/[0.06] bg-zinc-950/60">
      <div className="flex items-center gap-2.5 border-b border-white/[0.06] px-5 py-4">
        <div className="flex h-7 w-7 items-center justify-center rounded-lg bg-violet-600/20 text-violet-400">
          <Shield className="h-4 w-4" strokeWidth={1.75} />
        </div>
        <div>
          <div className="text-sm font-semibold tracking-tight text-zinc-50">Blacknet</div>
          <div className="text-[10px] leading-none text-zinc-600">network-wide DNS filter</div>
        </div>
      </div>
      <nav className="flex-1 overflow-y-auto px-3 py-3">
        {sections.map(sec => (
          <div key={sec.label} className="mb-4">
            <div className="px-2 pb-1.5 text-[10px] font-semibold uppercase tracking-[0.1em] text-zinc-600">
              {sec.label}
            </div>
            {sec.items.map(({ to, label, icon: Icon, end }) => (
              <NavLink
                key={to}
                to={to}
                end={end}
                className={({ isActive }) =>
                  `mb-0.5 flex items-center gap-2.5 rounded-lg px-2.5 py-[7px] text-[13px] font-medium transition-colors ${
                    isActive
                      ? 'bg-violet-500/15 text-violet-200'
                      : 'text-zinc-400 hover:bg-white/[0.04] hover:text-zinc-100'
                  }`
                }
              >
                <Icon className="h-4 w-4 shrink-0" strokeWidth={1.75} />
                {label}
              </NavLink>
            ))}
          </div>
        ))}
      </nav>
      <div className="border-t border-white/[0.06] px-5 py-3">
        <div className="flex items-center gap-2">
          <span className={`inline-block h-1.5 w-1.5 rounded-full ${protectionOn === false ? 'bg-red-400' : 'bg-emerald-400 shadow-[0_0_6px_1px_rgba(52,211,153,0.6)]'}`} />
          <span className="text-xs text-zinc-500">{protectionOn === false ? 'Protection off' : 'v' + version}</span>
        </div>
      </div>
    </aside>
  )
}
