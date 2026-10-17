import { useCallback, useEffect, useState } from 'react'
import { BrowserRouter, Route, Routes, useNavigate } from 'react-router-dom'
import { api, setUnauthorizedHandler } from './lib/api'
import { Sidebar } from './components/Sidebar'
import { Overview } from './pages/Overview'
import { QueryLog } from './pages/QueryLog'
import { Clients } from './pages/Clients'
import { Blocklists } from './pages/Blocklists'
import { Rules } from './pages/Rules'
import { Upstreams } from './pages/Upstreams'
import { NetworkSetup } from './pages/NetworkSetup'
import { Analytics } from './pages/Analytics'
import { SettingsPage } from './pages/Settings'
import { About } from './pages/About'
import { Login } from './pages/Login'
import { SetupWizard } from './pages/SetupWizard'
import { Loading } from './components/ui'

interface AuthState { password_set: boolean; authenticated: boolean; setup_completed: boolean }

function Shell() {
  const [auth, setAuth] = useState<AuthState | null>(null)
  const [version, setVersion] = useState('')
  const navigate = useNavigate()

  const refresh = useCallback(() => {
    api.get<AuthState>('/api/v1/auth/state').then(setAuth).catch(() => setAuth(null))
    api.get<{ version: string }>('/api/v1/health').then(h => setVersion(h.version)).catch(() => {})
  }, [])

  useEffect(() => {
    setUnauthorizedHandler(() => setAuth(a => a ? { ...a, authenticated: false } : a))
    refresh()
  }, [refresh])

  if (auth === null) return <div className="flex h-full items-center justify-center"><Loading /></div>

  if (!auth.password_set) {
    return <SetupWizard onDone={refresh} />
  }
  if (!auth.authenticated) {
    return <Login onDone={refresh} />
  }

  return (
    <div className="flex h-full">
      <Sidebar version={version} />
      <main className="flex-1 overflow-y-auto">
        <div className="mx-auto max-w-6xl px-6 py-6">
          <Routes>
            <Route path="/" element={<Overview />} />
            <Route path="/queries" element={<QueryLog />} />
            <Route path="/clients" element={<Clients />} />
            <Route path="/blocklists" element={<Blocklists />} />
            <Route path="/rules" element={<Rules />} />
            <Route path="/upstreams" element={<Upstreams />} />
            <Route path="/network" element={<NetworkSetup />} />
            <Route path="/analytics" element={<Analytics />} />
            <Route path="/settings" element={<SettingsPage onChanged={() => navigate(0)} />} />
            <Route path="/about" element={<About />} />
            <Route path="*" element={<Overview />} />
          </Routes>
        </div>
      </main>
    </div>
  )
}

export default function App() {
  return (
    <BrowserRouter>
      <Shell />
    </BrowserRouter>
  )
}
