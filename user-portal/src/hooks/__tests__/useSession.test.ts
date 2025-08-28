import { renderHook, waitFor } from '@testing-library/react'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { useSession } from '../useSession'

// Mock fetch
const mockFetch = vi.fn()
global.fetch = mockFetch

describe('useSession', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    // Mock localStorage
    Object.defineProperty(window, 'localStorage', {
      value: {
        getItem: vi.fn(),
        setItem: vi.fn(),
        removeItem: vi.fn(),
      },
      writable: true,
    })
  })

  it('initializes with loading state', () => {
    const { result } = renderHook(() => useSession())
    
    expect(result.current.isLoading).toBe(true)
    expect(result.current.sessions).toEqual([])
    expect(result.current.error).toBeNull()
  })

  it('fetches sessions successfully', async () => {
    const mockSessions = [
      {
        id: 'session-1',
        device: 'Chrome on Windows',
        location: 'New York, US',
        lastActive: '2024-01-01T12:00:00Z',
        current: true
      },
      {
        id: 'session-2',
        device: 'Safari on iPhone',
        location: 'Los Angeles, US',
        lastActive: '2024-01-01T10:00:00Z',
        current: false
      }
    ]

    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({ sessions: mockSessions })
    })

    const { result } = renderHook(() => useSession())

    await waitFor(() => {
      expect(result.current.isLoading).toBe(false)
      expect(result.current.sessions).toEqual(mockSessions)
      expect(result.current.error).toBeNull()
    })
  })

  it('handles API errors', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 500,
      json: () => Promise.resolve({ error: 'Internal Server Error' })
    })

    const { result } = renderHook(() => useSession())

    await waitFor(() => {
      expect(result.current.isLoading).toBe(false)
      expect(result.current.sessions).toEqual([])
      expect(result.current.error).toBe('Failed to fetch sessions')
    })
  })

  it('handles network errors', async () => {
    mockFetch.mockRejectedValueOnce(new Error('Network error'))

    const { result } = renderHook(() => useSession())

    await waitFor(() => {
      expect(result.current.isLoading).toBe(false)
      expect(result.current.sessions).toEqual([])
      expect(result.current.error).toBe('Failed to fetch sessions')
    })
  })

  it('revokes sessions successfully', async () => {
    const mockSessions = [
      {
        id: 'session-1',
        device: 'Chrome on Windows',
        location: 'New York, US',
        lastActive: '2024-01-01T12:00:00Z',
        current: true
      },
      {
        id: 'session-2',
        device: 'Safari on iPhone',
        location: 'Los Angeles, US',
        lastActive: '2024-01-01T10:00:00Z',
        current: false
      }
    ]

    // Initial fetch
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({ sessions: mockSessions })
    })

    // Revoke session
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({ success: true })
    })

    // Refetch after revoke
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({ 
        sessions: mockSessions.filter(s => s.id !== 'session-2')
      })
    })

    const { result } = renderHook(() => useSession())

    await waitFor(() => {
      expect(result.current.sessions).toHaveLength(2)
    })

    await result.current.revokeSession('session-2')

    expect(mockFetch).toHaveBeenCalledWith(
      expect.stringContaining('/api/sessions/session-2'),
      expect.objectContaining({
        method: 'DELETE',
        headers: expect.objectContaining({
          'Authorization': expect.stringContaining('Bearer')
        })
      })
    )

    await waitFor(() => {
      expect(result.current.sessions).toHaveLength(1)
      expect(result.current.sessions[0].id).toBe('session-1')
    })
  })

  it('handles session revocation errors', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({ sessions: [] })
    })

    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 403,
      json: () => Promise.resolve({ error: 'Unauthorized' })
    })

    const { result } = renderHook(() => useSession())

    await waitFor(() => {
      expect(result.current.isLoading).toBe(false)
    })

    const revokeResult = await result.current.revokeSession('session-1')
    expect(revokeResult).toBe(false)
  })

  it('refreshes sessions data', async () => {
    const initialSessions = [{ id: 'session-1', device: 'Chrome', location: 'US', lastActive: '2024-01-01T12:00:00Z', current: true }]
    const refreshedSessions = [{ id: 'session-1', device: 'Chrome', location: 'US', lastActive: '2024-01-01T13:00:00Z', current: true }]

    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({ sessions: initialSessions })
    })

    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({ sessions: refreshedSessions })
    })

    const { result } = renderHook(() => useSession())

    await waitFor(() => {
      expect(result.current.sessions[0].lastActive).toBe('2024-01-01T12:00:00Z')
    })

    await result.current.refreshSessions()

    await waitFor(() => {
      expect(result.current.sessions[0].lastActive).toBe('2024-01-01T13:00:00Z')
    })
  })

  it('includes authorization header in requests', async () => {
    window.localStorage.getItem = vi.fn().mockReturnValue('mock-token')

    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({ sessions: [] })
    })

    renderHook(() => useSession())

    await waitFor(() => {
      expect(mockFetch).toHaveBeenCalledWith(
        expect.stringContaining('/api/sessions'),
        expect.objectContaining({
          headers: expect.objectContaining({
            'Authorization': 'Bearer mock-token'
          })
        })
      )
    })
  })
})