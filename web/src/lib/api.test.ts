import { describe, it, expect, vi, beforeEach } from 'vitest'
import { api, ApiError, fmtNum, fmtTimeShort, setUnauthorizedHandler } from './api'

describe('fmtNum', () => {
  it('formats counts', () => {
    expect(fmtNum(42)).toBe('42')
    expect(fmtNum(1500)).toBe('1.5k')
    expect(fmtNum(2_500_000)).toBe('2.5M')
  })
})

describe('fmtTimeShort', () => {
  it('handles empty input', () => {
    expect(fmtTimeShort(undefined)).toBe('')
  })
})

describe('api client', () => {
  beforeEach(() => { vi.restoreAllMocks() })

  it('sends X-Requested-With for CSRF protection', async () => {
    const spy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response('{"ok":true}', { status: 200, headers: { 'Content-Type': 'application/json' } }))
    await api.get('/api/v1/status')
    const init = spy.mock.calls[0][1] as RequestInit
    expect((init.headers as Record<string, string>)['X-Requested-With']).toBe('XMLHttpRequest')
  })

  it('throws ApiError with server message', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response('{"error":"duplicate entry"}', { status: 409, headers: { 'Content-Type': 'application/json' } }))
    await expect(api.post('/api/v1/rules', { domain: 'x' })).rejects.toMatchObject({
      status: 409, message: 'duplicate entry',
    })
  })

  it('calls the unauthorized handler on 401', async () => {
    const cb = vi.fn()
    setUnauthorizedHandler(cb)
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response('{"error":"auth"}', { status: 401, headers: { 'Content-Type': 'application/json' } }))
    await expect(api.get('/api/v1/status')).rejects.toBeInstanceOf(ApiError)
    expect(cb).toHaveBeenCalled()
  })
})
