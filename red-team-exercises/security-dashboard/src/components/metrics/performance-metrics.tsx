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
  // Memoize all calculations together for better performance
  const { chartData, currentMetric, avgResponseTime, avgErrorRate, maxConnections } = useMemo(() => {
    if (!metrics || metrics.length === 0) {
      return {
        chartData: [],
        currentMetric: null,
        avgResponseTime: 0,
        avgErrorRate: 0,
        maxConnections: 0
      }
    }

    // Calculate all metrics in a single pass for better performance
    let totalResponseTime = 0
    let totalErrorRate = 0
    let maxConn = 0

    const recentMetrics = metrics.slice(-50) // Show last 50 data points
    const processedChartData = recentMetrics.map(metric => {
      // Accumulate values while processing chart data
      totalResponseTime += metric.responseTime
      totalErrorRate += metric.errorRate
      maxConn = Math.max(maxConn, metric.activeConnections)

      return {
        time: format(new Date(metric.timestamp), 'HH:mm:ss'),
        responseTime: metric.responseTime * 1000, // Convert to ms
        errorRate: metric.errorRate * 100, // Convert to percentage
        activeConnections: metric.activeConnections,
        throughput: (metric.authenticationSuccess + metric.authenticationFailure) || 0,
      }
    })

    return {
      chartData: processedChartData,
      currentMetric: metrics[0],
      avgResponseTime: (totalResponseTime / recentMetrics.length) * 1000,
      avgErrorRate: (totalErrorRate / recentMetrics.length) * 100,
      maxConnections: maxConn
    }
  }, [metrics])

  const CustomTooltip = useMemo(() => ({ active, payload, label }: any) => {
    if (!active || !payload || payload.length === 0) {
      return null
    }

    return (
      <div className="bg-background border rounded-lg shadow-lg p-3">
        <p className="text-sm font-medium mb-2">{`Time: ${label}`}</p>
        {payload.map((entry: any, index: number) => {
          const value = typeof entry.value === 'number' ? entry.value.toLocaleString() : entry.value
          const unit = entry.dataKey === 'responseTime' ? 'ms' : 
                      entry.dataKey === 'errorRate' ? '%' : ''
          
          return (
            <p key={index} className="text-sm" style={{ color: entry.color }}>
              {`${entry.name}: ${value}${unit}`}
            </p>
          )
        })}
      </div>
    )
  }, [])

  // Early return for empty metrics to avoid unnecessary rendering
  if (!metrics || metrics.length === 0) {
    return (
      <div className="space-y-6">
        <div className="text-center py-8">
          <p className="text-muted-foreground">No performance metrics available</p>
        </div>
      </div>
    )
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
              Avg: {Math.round(avgResponseTime)}ms
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
              {currentMetric ? Math.round(currentMetric.errorRate * 100 * 10) / 10 : 0}%
            </div>
            <div className="text-xs text-muted-foreground">
              Avg: {Math.round(avgErrorRate * 10) / 10}%
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
              value={maxConnections > 0 ? (currentMetric?.activeConnections || 0) / maxConnections * 100 : 0} 
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