import React from 'react'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { RealTimeAlerts } from '../alerts/real-time-alerts'
import { AuthContext } from '../../contexts/AuthContext'
import type { SecurityAlert } from '../../types/security'

// Mock the AuthContext
const mockAuthContext = {
  currentUser: { id: 'test-user', email: 'test@example.com' },
  isAuthenticated: true,
  login: vi.fn(),
  logout: vi.fn(),
  refreshToken: vi.fn(),
  getAuthToken: vi.fn().mockResolvedValue('mock-token')
}

const mockAlerts: SecurityAlert[] = [
  {
    id: 'alert-1',
    type: 'security_breach',
    severity: 'high',
    title: 'Suspicious Login Detected',
    description: 'Multiple failed login attempts from unknown IP',
    timestamp: '2024-01-01T12:00:00Z',
    source: 'auth-service',
    metadata: {},
    correlatedEvents: [],
    acknowledged: false
  },
  {
    id: 'alert-2',
    type: 'rate_limit_exceeded',
    severity: 'medium',
    title: 'Rate Limit Exceeded',
    description: 'API rate limit exceeded for client',
    timestamp: '2024-01-01T11:30:00Z',
    source: 'api-gateway',
    metadata: {},
    correlatedEvents: [],
    acknowledged: false
  }
]

const renderWithAuth = (component: React.ReactElement) => {
  return render(
    <AuthContext.Provider value={mockAuthContext}>
      {component}
    </AuthContext.Provider>
  )
}

describe('RealTimeAlerts', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    global.fetch = vi.fn()
  })

  it('renders alerts correctly', () => {
    renderWithAuth(<RealTimeAlerts alerts={mockAlerts} />)

    expect(screen.getByText('Suspicious Login Detected')).toBeInTheDocument()
    expect(screen.getByText('Rate Limit Exceeded')).toBeInTheDocument()
  })

  it('displays alert severity levels', () => {
    renderWithAuth(<RealTimeAlerts alerts={mockAlerts} />)

    // Should show high and medium severity badges
    expect(screen.getByText('high')).toBeInTheDocument()
    expect(screen.getByText('medium')).toBeInTheDocument()
  })

  it('limits alerts to maximum of 5', () => {
    const manyAlerts = Array.from({ length: 10 }, (_, i) => ({
      id: `alert-${i}`,
      type: 'security_breach',
      severity: 'low',
      title: `Alert ${i}`,
      description: `Description ${i}`,
      timestamp: '2024-01-01T12:00:00Z',
      source: 'test',
      metadata: {},
    correlatedEvents: [],
    acknowledged: false
    }))

    renderWithAuth(<RealTimeAlerts alerts={manyAlerts} />)

    const alertElements = screen.getAllByText(/Alert \d+/)
    expect(alertElements).toHaveLength(5)
  })

  it('handles alert dismissal', async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      ok: true,
      headers: {
        get: (name: string) => name === 'content-type' ? 'application/json' : null
      },
      json: () => Promise.resolve({ success: true })
    })
    global.fetch = mockFetch

    renderWithAuth(<RealTimeAlerts alerts={mockAlerts} />)

    const dismissButtons = screen.getAllByRole('button')
    fireEvent.click(dismissButtons[0])

    await waitFor(() => {
      expect(mockFetch).toHaveBeenCalledWith(
        expect.stringContaining('/api/alerts/alert-1/acknowledge'),
        expect.objectContaining({
          method: 'POST',
          headers: expect.objectContaining({
            'Authorization': 'Bearer mock-token'
          })
        })
      )
    })
  })

  it('shows loading state during alert acknowledgment', async () => {
    const mockFetch = vi.fn().mockImplementation(
      () => new Promise(resolve => setTimeout(resolve, 100))
    )
    global.fetch = mockFetch

    renderWithAuth(<RealTimeAlerts alerts={mockAlerts} />)

    const dismissButton = screen.getAllByRole('button')[0]
    fireEvent.click(dismissButton)

    expect(dismissButton).toBeDisabled()
  })

  it('handles API errors gracefully', async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 500,
      headers: {
        get: (name: string) => name === 'content-type' ? 'application/json' : null
      }
    })
    global.fetch = mockFetch

    renderWithAuth(<RealTimeAlerts alerts={mockAlerts} />)

    const dismissButton = screen.getAllByRole('button')[0]
    fireEvent.click(dismissButton)

    await waitFor(() => {
      // Alert should still be visible after failed acknowledgment
      expect(screen.getByText('Suspicious Login Detected')).toBeInTheDocument()
    })
  })

  it('filters out dismissed alerts', async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      ok: true,
      headers: {
        get: (name: string) => name === 'content-type' ? 'application/json' : null
      },
      json: () => Promise.resolve({ success: true })
    })
    global.fetch = mockFetch

    renderWithAuth(<RealTimeAlerts alerts={mockAlerts} />)

    expect(screen.getByText('Suspicious Login Detected')).toBeInTheDocument()

    const dismissButton = screen.getAllByRole('button')[0]
    fireEvent.click(dismissButton)

    await waitFor(() => {
      expect(screen.queryByText('Suspicious Login Detected')).not.toBeInTheDocument()
    })
  })
})
