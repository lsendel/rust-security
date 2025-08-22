import { useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { AlertTriangle, X, Eye, ExternalLink } from 'lucide-react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { SecurityAlert } from '@/types/security'
import { formatRelativeTime } from '@/lib/utils'

interface RealTimeAlertsProps {
  alerts: SecurityAlert[]
}

export function RealTimeAlerts({ alerts }: RealTimeAlertsProps) {
  const [dismissedAlerts, setDismissedAlerts] = useState<Set<string>>(new Set())

  const visibleAlerts = alerts
    .filter(alert => !dismissedAlerts.has(alert.id))
    .slice(0, 5) // Show only top 5 alerts

  const dismissAlert = (alertId: string) => {
    setDismissedAlerts(prev => new Set([...prev, alertId]))
  }

  const acknowledgeAlert = async (alertId: string) => {
    try {
      // Call API to acknowledge alert
      const response = await fetch(`/api/alerts/${alertId}/acknowledge`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${localStorage.getItem('auth_token')}`,
        },
        body: JSON.stringify({
          acknowledged_at: new Date().toISOString(),
          acknowledged_by: 'current_user', // Would come from auth context
        }),
      })
      
      if (!response.ok) {
        throw new Error(`Failed to acknowledge alert: ${response.statusText}`)
      }
      
      const result = await response.json()
      console.warn('Alert acknowledged successfully:', result)
      
      // Update local state to reflect acknowledgment
      setDismissedAlerts(prev => new Set([...prev, alertId]))
      
      // Show success notification
      // You could use a toast library here
      console.warn(`Alert ${alertId} has been acknowledged`)
      
    } catch (error) {
      console.error('Error acknowledging alert:', error)
      // Handle error (show toast, etc.)
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