import { useEffect, useState } from 'react'
import { Radar, Check, Info } from 'lucide-react'
import { api, fmtTime } from '../lib/api'
import { DiscoveryEvent } from '../lib/types'
import { Badge, EmptyState, ErrorBox, Loading } from '../components/ui'

interface EventsResp {
  items: DiscoveryEvent[]
  enabled: boolean
  host_interfaces: { name: string; addrs: string[]; ipv4: string[]; is_up: boolean; is_loopback: boolean }[]
}

export function Devices() {
  const [data, setData] = useState<EventsResp | null>(null)
  const [err, setErr] = useState<unknown>(null)
  const [scanning, setScanning] = useState(false)

  const load = () => api.get<EventsResp>('/api/v1/discovery/events?limit=200')
    .then(setData).catch(setErr)
  useEffect(() => { load() }, [])

  const scan = async () => {
    setScanning(true)
    try {
      await api.post('/api/v1/discovery/scan')
      setTimeout(load, 2500)
    } catch (e) { setErr(e) }
    setScanning(false)
  }
  const ack = async (e: DiscoveryEvent) => {
    await api.post(`/api/v1/discovery/events/${e.id}/ack`).then(load).catch(setErr)
  }

  if (!data) return err ? <ErrorBox error={err} /> : <Loading />
  const items = data.items ?? []
  const unacked = items.filter(e => !e.notified)

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-lg font-semibold text-zinc-100">Device Discovery</h1>
        <button className="btn-primary" disabled={scanning || !data.enabled} onClick={scan}>
          <Radar className="h-3.5 w-3.5" /> {scanning ? 'Scanning…' : 'Scan now'}
        </button>
      </div>
      <ErrorBox error={err} />

      {!data.enabled ? (
        <div className="card flex items-start gap-3 p-4">
          <Info className="mt-0.5 h-4 w-4 shrink-0 text-zinc-500" />
          <div className="text-sm text-zinc-400">
            Passive discovery is disabled. Enable it under Settings → Discovery to watch the neighbor
            table and DHCP leases for new devices.
          </div>
        </div>
      ) : (
        <div className="card flex items-start gap-3 p-4">
          <Info className="mt-0.5 h-4 w-4 shrink-0 text-zinc-500" />
          <div className="text-sm text-zinc-400">
            {unacked.length > 0
              ? `${unacked.length} unacknowledged event${unacked.length === 1 ? '' : 's'}.`
              : 'All events acknowledged.'}{' '}
            Discovery is passive — it reads the neighbor table and DHCP leases; nothing is probed.
          </div>
        </div>
      )}

      {items.length === 0 ? (
        <EmptyState title="No discovery events" hint="New devices, MAC sightings and lease observations appear here." />
      ) : (
        <div className="card overflow-x-auto">
          <table className="w-full min-w-[720px]">
            <thead><tr>
              <th className="th">Kind</th><th className="th">Value</th><th className="th">Detail</th>
              <th className="th">First seen</th><th className="th">Last seen</th>
              <th className="th text-right">Count</th><th className="th" />
            </tr></thead>
            <tbody>
              {items.map(e => (
                <tr key={e.id} className={e.notified ? '' : 'bg-violet-950/10 hover:bg-violet-950/20'}>
                  <td className="td"><Badge tone={e.notified ? 'muted' : 'accent'}>{e.kind}</Badge></td>
                  <td className="td font-mono text-xs">{e.value}</td>
                  <td className="td max-w-[260px] truncate text-xs text-zinc-500">{e.detail || '—'}</td>
                  <td className="td text-xs text-zinc-500 whitespace-nowrap">{fmtTime(e.first_seen)}</td>
                  <td className="td text-xs text-zinc-500 whitespace-nowrap">{fmtTime(e.last_seen)}</td>
                  <td className="td text-right text-xs text-zinc-400">{e.count}</td>
                  <td className="td text-right">
                    {!e.notified && (
                      <button className="btn-ghost px-2!" title="Acknowledge" onClick={() => ack(e)}>
                        <Check className="h-3.5 w-3.5" />
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {(data.host_interfaces ?? []).length > 0 && (
        <>
          <h2 className="pt-2 text-sm font-semibold text-zinc-200">Host interfaces</h2>
          <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
            {data.host_interfaces.filter(i => i.is_up && !i.is_loopback).map(i => (
              <div key={i.name} className="card px-3 py-2">
                <div className="text-xs font-medium text-zinc-300">{i.name}</div>
                <div className="mt-0.5 font-mono text-xs text-zinc-500">{(i.ipv4 ?? []).join(', ') || '—'}</div>
              </div>
            ))}
          </div>
        </>
      )}
    </div>
  )
}
