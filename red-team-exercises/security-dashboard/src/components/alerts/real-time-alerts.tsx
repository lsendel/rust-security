import React, { useState, useContext } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { AlertTriangle, X, Eye, ExternalLink } from 'lucide-react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { SecurityAlert } from '@/types/security'
import { formatRelativeTime } from '@/lib/utils'
import { AuthContext } from '@/contexts/AuthContext'

interface RealTimeAlertsProps {
  alerts: SecurityAlert[]
}

export function RealTimeAlerts({ alerts }: RealTimeAlertsProps) {
  const [dismissedAlerts, setDismissedAlerts] = useState<Set<string>>(new Set())
  const [loadingAlerts, setLoadingAlerts] = useState<Set<string>>(new Set())
  const authContext = useContext(AuthContext)
  if (!authContext) {
    throw new Error('RealTimeAlerts must be used within an AuthProvider')
  }
  const { getAuthToken, currentUser } = authContext

  const visibleAlerts = alerts
    .filter(alert => !dismissedAlerts.has(alert.id))
    .slice(0, 5) // Show only top 5 alerts

  const dismissAlert = (alertId: string) => {
    setDismissedAlerts(prev => new Set([...prev, alertId]))
  }

  const acknowledgeAlert = async (alertId: string) => {
    // Validate alertId format
    if (!alertId || typeof alertId !== 'string' || !/^[a-zA-Z0-9-_]+$/.test(alertId)) {
      console.error('Invalid alert ID format')
      return
    }

    // Set loading state
    setLoadingAlerts(prev => new Set([...prev, alertId]))

    try {
      const authToken = await getAuthToken() // Secure token retrieval
      if (!authToken) {
        throw new Error('Authentication required')
      }

      // Call API to acknowledge alert
      const response = await fetch(`/api/alerts/${encodeURIComponent(alertId)}/acknowledge`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${authToken}`,
        },
        body: JSON.stringify({
          acknowledged_at: new Date().toISOString(),
          acknowledged_by: currentUser?.id || 'unknown',
        }),
      })

      if (!response.ok) {
        throw new Error(`Failed to acknowledge alert: ${response.statusText}`)
      }

      // Validate response
      const contentType = response.headers.get('content-type')
      if (!contentType || !contentType.includes('application/json')) {
        throw new Error('Invalid response format')
      }

      const result = await response.json()
      
      // Validate response structure
      if (typeof result !== 'object' || !result.success) {
        throw new Error('Invalid response structure')
      }

      // Alert acknowledged successfully

      // Update local state to reflect acknowledgment
      setDismissedAlerts(prev => new Set([...prev, alertId]))

    } catch (error) {
      console.error('Error acknowledging alert:', error)
      // Handle error (show toast, etc.)
    } finally {
      // Clear loading state
      setLoadingAlerts(prev => {
        const newSet = new Set(prev)
        newSet.delete(alertId)
        return newSet
      })
    }
  }

  if (visibleAlerts.length === 0) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <AlertTriangle className="h-5 w-5 text-green-500" />
            Security Alerts
          </CardTitle>
          <CardDescription>Real-time security notifications</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="text-center py-8 text-muted-foreground">
            <AlertTriangle className="h-12 w-12 mx-auto mb-4 text-green-500" />
            <p className="text-lg font-medium">All Clear!</p>
            <p className="text-sm">No active security alerts</p>
          </div>
        </CardContent>
      </Card>
    )
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <AlertTriangle className="h-5 w-5 text-orange-500" />
          Security Alerts
          <Badge variant="destructive" className="ml-auto">
            {visibleAlerts.length}
          </Badge>
        </CardTitle>
        <CardDescription>Real-time security notifications</CardDescription>
      </CardHeader>
      <CardContent>
        <div className="space-y-3">
          <AnimatePresence>
            {visibleAlerts.map((alert) => (
              <motion.div
                key={alert.id}
                initial={{ opacity: 0, x: 20 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, x: -20 }}
                className={`border rounded-lg p-3 ${
                  alert.severity === 'critical'
                    ? 'border-red-500 bg-red-50 dark:bg-red-950/10'
                    : 'border-orange-500 bg-orange-50 dark:bg-orange-950/10'
                }`}
              >
                <div className="flex items-start justify-between">
                  <div className="flex-1">
                    <div className="flex items-center gap-2 mb-1">
                      <Badge
                        variant={alert.severity === 'critical' ? 'destructive' : 'outline'}
                        className={alert.severity === 'critical' ? 'animate-pulse' : ''}
                      >
                        {alert.severity}
                      </Badge>
                      <span className="text-sm font-medium">{alert.title}</span>
                    </div>
                    <p className="text-sm text-muted-foreground mb-2">
                      {alert.description}
                    </p>
                    <div className="flex items-center gap-2 text-xs text-muted-foreground">
                      <span>Source: {alert.source}</span>
                      <span>•</span>
                      <span>{formatRelativeTime(alert.timestamp)}</span>
                      {alert.assignedTo && (
                        <>
                          <span>•</span>
                          <span>Assigned to: {alert.assignedTo}</span>
                        </>
                      )}
                    </div>
                  </div>
                  <div className="flex items-center gap-1 ml-2">
                    {!alert.acknowledged && (
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => acknowledgeAlert(alert.id)}
                        disabled={loadingAlerts.has(alert.id)}
                      >
                        <Eye className="h-3 w-3" />
                      </Button>
                    )}
                    <Button
                      size="sm"
                      variant="ghost"
                      onClick={() => dismissAlert(alert.id)}
                    >
                      <X className="h-3 w-3" />
                    </Button>
                  </div>
                </div>

                {alert.correlatedEvents.length > 0 && (
                  <div className="mt-2 pt-2 border-t">
                    <p className="text-xs text-muted-foreground">
                      Correlated with {alert.correlatedEvents.length} other events
                    </p>
                  </div>
                )}
              </motion.div>
            ))}
          </AnimatePresence>
        </div>

        {alerts.length > 5 && (
          <div className="mt-3 pt-3 border-t text-center">
            <Button variant="outline" size="sm">
              <ExternalLink className="h-4 w-4 mr-2" />
              View All {alerts.length} Alerts
            </Button>
          </div>
        )}
      </CardContent>
    </Card>
  )
}
