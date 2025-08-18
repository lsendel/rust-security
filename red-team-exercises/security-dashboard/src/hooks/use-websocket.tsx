import React, { createContext, useContext, useEffect, useRef, useState } from 'react'
import { io, Socket } from 'socket.io-client'
import { SecurityMetrics, ThreatEvent, SecurityAlert } from '@/types/security'

interface WebSocketContextType {
  socket: Socket | null
  connected: boolean
  securityMetrics: SecurityMetrics | null
  recentThreats: ThreatEvent[]
  activeAlerts: SecurityAlert[]
  subscribe: (event: string, callback: (data: any) => void) => () => void
  emit: (event: string, data?: any) => void
}

const WebSocketContext = createContext<WebSocketContextType | undefined>(undefined)

interface WebSocketProviderProps {
  children: React.ReactNode
  url: string
}

export function WebSocketProvider({ children, url }: WebSocketProviderProps) {
  const [socket, setSocket] = useState<Socket | null>(null)
  const [connected, setConnected] = useState(false)
  const [securityMetrics, setSecurityMetrics] = useState<SecurityMetrics | null>(null)
  const [recentThreats, setRecentThreats] = useState<ThreatEvent[]>([])
  const [activeAlerts, setActiveAlerts] = useState<SecurityAlert[]>([])
  const reconnectAttempts = useRef(0)
  const maxReconnectAttempts = 5

  useEffect(() => {
    const socketInstance = io(url, {
      transports: ['websocket'],
      upgrade: true,
      rememberUpgrade: true,
      timeout: 20000,
      forceNew: true,
    })

    socketInstance.on('connect', () => {
      console.log('WebSocket connected')
      setConnected(true)
      reconnectAttempts.current = 0
    })

    socketInstance.on('disconnect', (reason) => {
      console.log('WebSocket disconnected:', reason)
      setConnected(false)
      
      // Attempt to reconnect
      if (reconnectAttempts.current < maxReconnectAttempts) {
        reconnectAttempts.current++
        setTimeout(() => {
          socketInstance.connect()
        }, Math.pow(2, reconnectAttempts.current) * 1000) // Exponential backoff
      }
    })

    socketInstance.on('connect_error', (error) => {
      console.error('WebSocket connection error:', error)
      setConnected(false)
    })

    // Security-specific event handlers
    socketInstance.on('security-metrics', (data: SecurityMetrics) => {
      setSecurityMetrics(data)
    })

    socketInstance.on('threat-event', (data: ThreatEvent) => {
      setRecentThreats(prev => [data, ...prev.slice(0, 99)]) // Keep last 100 threats
    })

    socketInstance.on('security-alert', (data: SecurityAlert) => {
      setActiveAlerts(prev => {
        const existing = prev.find(alert => alert.id === data.id)
        if (existing) {
          return prev.map(alert => alert.id === data.id ? data : alert)
        }
        return [data, ...prev]
      })
    })

    socketInstance.on('alert-resolved', (alertId: string) => {
      setActiveAlerts(prev => prev.filter(alert => alert.id !== alertId))
    })

    setSocket(socketInstance)

    return () => {
      socketInstance.disconnect()
    }
  }, [url])

  const subscribe = (event: string, callback: (data: any) => void) => {
    if (!socket) return () => {}
    
    socket.on(event, callback)
    return () => socket.off(event, callback)
  }

  const emit = (event: string, data?: any) => {
    if (socket && connected) {
      socket.emit(event, data)
    }
  }

  const value: WebSocketContextType = {
    socket,
    connected,
    securityMetrics,
    recentThreats,
    activeAlerts,
    subscribe,
    emit,
  }

  return (
    <WebSocketContext.Provider value={value}>
      {children}
    </WebSocketContext.Provider>
  )
}

export function useWebSocket() {
  const context = useContext(WebSocketContext)
  if (context === undefined) {
    throw new Error('useWebSocket must be used within a WebSocketProvider')
  }
  return context
}

// Custom hooks for specific data types
export function useSecurityMetrics() {
  const { securityMetrics, subscribe } = useWebSocket()
  const [metrics, setMetrics] = useState<SecurityMetrics[]>([])

  useEffect(() => {
    if (securityMetrics) {
      setMetrics(prev => [securityMetrics, ...prev.slice(0, 99)])
    }
  }, [securityMetrics])

  useEffect(() => {
    return subscribe('security-metrics-batch', (batchData: SecurityMetrics[]) => {
      setMetrics(batchData)
    })
  }, [subscribe])

  return metrics
}

export function useThreatEvents() {
  const { recentThreats, subscribe } = useWebSocket()
  const [threats, setThreats] = useState<ThreatEvent[]>([])

  useEffect(() => {
    setThreats(recentThreats)
  }, [recentThreats])

  useEffect(() => {
    return subscribe('threat-events-batch', (batchData: ThreatEvent[]) => {
      setThreats(batchData)
    })
  }, [subscribe])

  return threats
}

export function useSecurityAlerts() {
  const { activeAlerts, subscribe } = useWebSocket()
  const [alerts, setAlerts] = useState<SecurityAlert[]>([])

  useEffect(() => {
    setAlerts(activeAlerts)
  }, [activeAlerts])

  useEffect(() => {
    return subscribe('alerts-batch', (batchData: SecurityAlert[]) => {
      setAlerts(batchData)
    })
  }, [subscribe])

  return alerts
}

export function useRealTimeData<T>(event: string, initialData: T[] = []) {
  const { subscribe } = useWebSocket()
  const [data, setData] = useState<T[]>(initialData)

  useEffect(() => {
    return subscribe(event, (newData: T) => {
      setData(prev => [newData, ...prev.slice(0, 99)])
    })
  }, [event, subscribe])

  useEffect(() => {
    return subscribe(`${event}-batch`, (batchData: T[]) => {
      setData(batchData)
    })
  }, [event, subscribe])

  return data
}