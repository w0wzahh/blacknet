import { useState } from 'react'
import { Shield } from 'lucide-react'
import { api } from '../lib/api'
import { ErrorBox } from '../components/ui'

export function Login({ onDone }: { onDone: () => void }) {
  const [password, setPassword] = useState('')
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    setBusy(true); setErr('')
    try {
      await api.post('/api/v1/auth/login', { password })
      onDone()
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'login failed')
      setBusy(false)
    }
  }

  return (
    <div className="flex h-full items-center justify-center bg-zinc-950">
      <form onSubmit={submit} className="card w-80 space-y-4 p-6">
        <div className="flex items-center gap-2">
          <Shield className="h-6 w-6 text-violet-400" strokeWidth={1.75} />
          <span className="text-base font-semibold text-zinc-100">Blacknet</span>
        </div>
        <label className="block">
          <span className="mb-1 block text-xs text-zinc-500">Admin password</span>
          <input
            type="password" autoFocus className="input w-full"
            value={password} onChange={e => setPassword(e.target.value)}
          />
        </label>
        {err && <ErrorBox error={err} />}
        <button className="btn-primary w-full justify-center" disabled={busy || !password}>
          {busy ? 'Signing in…' : 'Sign in'}
        </button>
      </form>
    </div>
  )
}
