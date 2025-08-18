import { useMemo } from 'react'
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
  AreaChart,
  Area
} from 'recharts'
import { format } from 'date-fns'
import { SecurityMetrics } from '@/types/security'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Progress } from '@/components/ui/progress'
import { Activity, Zap, Database, Wifi } from 'lucide-react'

interface PerformanceMetricsProps {
  metrics: SecurityMetrics[]
}

export function PerformanceMetrics({ metrics }: PerformanceMetricsProps) {
  const chartData = useMemo(() => {
    return metrics
      .slice(-50) // Show last 50 data points
      .map(metric => ({
        time: format(new Date(metric.timestamp), 'HH:mm:ss'),
        responseTime: metric.responseTime * 1000, // Convert to ms
        errorRate: metric.errorRate * 100, // Convert to percentage
        activeConnections: metric.activeConnections,
        throughput: (metric.authenticationSuccess + metric.authenticationFailure) || 0,
      }))
  }, [metrics])

  // Calculate current metrics
  const currentMetric = metrics[0]
  const avgResponseTime = metrics.reduce((sum, m) => sum + m.responseTime, 0) / metrics.length * 1000
  const avgErrorRate = metrics.reduce((sum, m) => sum + m.errorRate, 0) / metrics.length * 100
  const maxConnections = Math.max(...metrics.map(m => m.activeConnections))

  const CustomTooltip = ({ active, payload, label }: any) => {
    if (active && payload && payload.length) {
      return (
        <div className="bg-background border rounded-lg shadow-lg p-3">
          <p className="text-sm font-medium mb-2">{`Time: ${label}`}</p>
          {payload.map((entry: any, index: number) => (
            <p key={index} className="text-sm" style={{ color: entry.color }}>
              {`${entry.name}: ${entry.value.toLocaleString()}`}
              {entry.dataKey === 'responseTime' && 'ms'}
              {entry.dataKey === 'errorRate' && '%'}
            </p>
          ))}
        </div>
      )
    }
    return null
  }

  return (
    <div className="space-y-6">
      {/* Performance Overview Cards */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <Card className="glass-effect">
          <CardContent className="p-4">
            <div className="flex items-center gap-2 mb-2">
              <Zap className="h-4 w-4 text-blue-500" />
              <span className="text-sm font-medium">Response Time</span>
            </div>
            <div className="text-2xl font-bold text-blue-500">
              {currentMetric ? Math.round(currentMetric.responseTime * 1000) : 0}ms
            </div>
            <div className="text-xs text-muted-foreground">
              Avg: {avgResponseTime.toFixed(0)}ms
            </div>
            <Progress 
              value={Math.min((avgResponseTime / 1000) * 100, 100)} 
              className="mt-2 h-1" 
            />
          </CardContent>
        </Card>

        <Card className="glass-effect">
          <CardContent className="p-4">
            <div className="flex items-center gap-2 mb-2">
              <Activity className="h-4 w-4 text-red-500" />
              <span className="text-sm font-medium">Error Rate</span>
            </div>
            <div className="text-2xl font-bold text-red-500">
              {currentMetric ? (currentMetric.errorRate * 100).toFixed(1) : 0}%
            </div>
            <div className="text-xs text-muted-foreground">
              Avg: {avgErrorRate.toFixed(1)}%
            </div>
            <Progress 
              value={avgErrorRate} 
              className="mt-2 h-1" 
            />
          </CardContent>
        </Card>

        <Card className="glass-effect">
          <CardContent className="p-4">
            <div className="flex items-center gap-2 mb-2">
              <Wifi className="h-4 w-4 text-green-500" />
              <span className="text-sm font-medium">Active Connections</span>
            </div>
            <div className="text-2xl font-bold text-green-500">
              {currentMetric ? currentMetric.activeConnections.toLocaleString() : 0}
            </div>
            <div className="text-xs text-muted-foreground">
              Peak: {maxConnections.toLocaleString()}
            </div>
            <Progress 
              value={(currentMetric?.activeConnections || 0) / maxConnections * 100} 
              className="mt-2 h-1" 
            />
          </CardContent>
        </Card>

        <Card className="glass-effect">
          <CardContent className="p-4">
            <div className="flex items-center gap-2 mb-2">
              <Database className="h-4 w-4 text-purple-500" />
              <span className="text-sm font-medium">Throughput</span>
            </div>
            <div className="text-2xl font-bold text-purple-500">
              {chartData[chartData.length - 1]?.throughput?.toLocaleString() || 0}
            </div>
            <div className="text-xs text-muted-foreground">
              Requests/min
            </div>
            <Progress 
              value={75} 
              className="mt-2 h-1" 
            />
          </CardContent>
        </Card>
      </div>

      {/* Performance Charts */}
      <div className="grid gap-4 md:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Response Time & Error Rate</CardTitle>
            <CardDescription>
              System performance metrics over time
            </CardDescription>
          </CardHeader>
          <CardContent>
            <ResponsiveContainer width="100%" height={300}>
              <LineChart data={chartData}>
                <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" />
                <XAxis 
                  dataKey="time" 
                  stroke="hsl(var(--muted-foreground))"
                  fontSize={12}
                />
                <YAxis 
                  yAxisId="left"
                  stroke="hsl(var(--muted-foreground))" 
                  fontSize={12}
                  label={{ value: 'Response Time (ms)', angle: -90, position: 'insideLeft' }}
                />
                <YAxis 
                  yAxisId="right" 
                  orientation="right"
                  stroke="hsl(var(--muted-foreground))" 
                  fontSize={12}
                  label={{ value: 'Error Rate (%)', angle: 90, position: 'insideRight' }}
                />
                <Tooltip content={<CustomTooltip />} />
                <Legend />
                <Line
                  yAxisId="left"
                  type="monotone"
                  dataKey="responseTime"
                  stroke="#3b82f6"
                  strokeWidth={2}
                  name="Response Time (ms)"
                  dot={false}
                />
                <Line
                  yAxisId="right"
                  type="monotone"
                  dataKey="errorRate"
                  stroke="#ef4444"
                  strokeWidth={2}
                  name="Error Rate (%)"
                  dot={false}
                />
              </LineChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Connection Load</CardTitle>
            <CardDescription>
              Active connections and system throughput
            </CardDescription>
          </CardHeader>
          <CardContent>
            <ResponsiveContainer width="100%" height={300}>
              <AreaChart data={chartData}>
                <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" />
                <XAxis 
                  dataKey="time" 
                  stroke="hsl(var(--muted-foreground))"
                  fontSize={12}
                />
                <YAxis stroke="hsl(var(--muted-foreground))" fontSize={12} />
                <Tooltip content={<CustomTooltip />} />
                <Legend />
                <Area
                  type="monotone"
                  dataKey="activeConnections"
                  stackId="1"
                  stroke="#22c55e"
                  fill="#22c55e"
                  fillOpacity={0.6}
                  name="Active Connections"
                />
                <Area
                  type="monotone"
                  dataKey="throughput"
                  stackId="2"
                  stroke="#8b5cf6"
                  fill="#8b5cf6"
                  fillOpacity={0.6}
                  name="Throughput"
                />
              </AreaChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>
      </div>

      {/* Performance Alerts */}
      <Card>
        <CardHeader>
          <CardTitle>Performance Status</CardTitle>
          <CardDescription>
            Current system health and performance indicators
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-3">
            <div className="flex items-center justify-between p-3 border rounded-lg">
              <div className="flex items-center gap-3">
                <div className="w-2 h-2 bg-green-500 rounded-full"></div>
                <div>
                  <div className="font-medium">Response Time</div>
                  <div className="text-sm text-muted-foreground">
                    Within acceptable limits (&lt; 500ms)
                  </div>
                </div>
              </div>
              <Badge variant="outline" className="text-green-500">Healthy</Badge>
            </div>

            <div className="flex items-center justify-between p-3 border rounded-lg">
              <div className="flex items-center gap-3">
                <div className="w-2 h-2 bg-yellow-500 rounded-full"></div>
                <div>
                  <div className="font-medium">Error Rate</div>
                  <div className="text-sm text-muted-foreground">
                    Slightly elevated but within thresholds
                  </div>
                </div>
              </div>
              <Badge variant="outline" className="text-yellow-500">Warning</Badge>
            </div>

            <div className="flex items-center justify-between p-3 border rounded-lg">
              <div className="flex items-center gap-3">
                <div className="w-2 h-2 bg-green-500 rounded-full"></div>
                <div>
                  <div className="font-medium">System Load</div>
                  <div className="text-sm text-muted-foreground">
                    Normal operation, sufficient capacity
                  </div>
                </div>
              </div>
              <Badge variant="outline" className="text-green-500">Optimal</Badge>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}