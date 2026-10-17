import { describe, it, expect, vi } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { Toggle, Modal, StatCard, EmptyState } from './ui'

describe('ui components', () => {
  it('Toggle fires onChange', () => {
    const fn = vi.fn()
    render(<Toggle on={false} onChange={fn} />)
    fireEvent.click(screen.getByRole('button'))
    expect(fn).toHaveBeenCalledWith(true)
  })

  it('Modal renders title and children', () => {
    render(<Modal title="Hello" onClose={() => {}}><div>body</div></Modal>)
    expect(screen.getByText('Hello')).toBeTruthy()
    expect(screen.getByText('body')).toBeTruthy()
  })

  it('StatCard renders label and value', () => {
    render(<StatCard label="Queries" value={1234} />)
    expect(screen.getByText('Queries')).toBeTruthy()
    expect(screen.getByText('1234')).toBeTruthy()
  })

  it('EmptyState renders hint', () => {
    render(<EmptyState title="none" hint="do a thing" />)
    expect(screen.getByText('do a thing')).toBeTruthy()
  })
})
