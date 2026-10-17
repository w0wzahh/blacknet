export class ApiError extends Error {
  status: number
  fields?: Record<string, string>
  constructor(status: number, message: string, fields?: Record<string, string>) {
    super(message)
    this.status = status
    this.fields = fields
  }
}

let onUnauthorized: (() => void) | null = null
export function setUnauthorizedHandler(fn: () => void) { onUnauthorized = fn }

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const res = await fetch(path, {
    method,
    headers: {
      'X-Requested-With': 'XMLHttpRequest',
      ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}),
    },
    body: body !== undefined ? JSON.stringify(body) : undefined,
    credentials: 'same-origin',
  })
  if (res.status === 401 && onUnauthorized && !path.includes('/auth/')) {
    onUnauthorized()
  }
  const ct = res.headers.get('content-type') || ''
  const data = ct.includes('json') ? await res.json() : await res.text()
  if (!res.ok) {
    const msg = typeof data === 'object' && data?.error ? data.error : res.statusText
    throw new ApiError(res.status, msg, typeof data === 'object' ? data?.fields : undefined)
  }
  if (!ct.includes('json')) {
    throw new ApiError(res.status, 'unexpected non-JSON response')
  }
  return data as T
}

export const api = {
  get: <T>(path: string) => request<T>('GET', path),
  post: <T>(path: string, body?: unknown) => request<T>('POST', path, body),
  patch: <T>(path: string, body?: unknown) => request<T>('PATCH', path, body),
  put: <T>(path: string, body?: unknown) => request<T>('PUT', path, body),
  del: <T>(path: string) => request<T>('DELETE', path),
}

export function fmtTime(iso?: string): string {
  if (!iso) return '—'
  const d = new Date(iso)
  return d.toLocaleString(undefined, {
    month: 'short', day: 'numeric',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
  })
}

export function fmtTimeShort(iso?: string): string {
  if (!iso) return ''
  const d = new Date(iso)
  return d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' })
}

export function fmtNum(n: number): string {
  if (n >= 1_000_000) return (n / 1_000_000).toFixed(1) + 'M'
  if (n >= 1_000) return (n / 1_000).toFixed(1) + 'k'
  return String(n)
}

// arr normalizes an API value to a real array — guards against null and
// non-array JSON (e.g. a wrapped {items:…} shape) so .map never throws.
export function arr<T>(v: unknown): T[] {
  return Array.isArray(v) ? v as T[] : []
}
