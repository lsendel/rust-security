import { useState, useMemo } from 'react'
import {
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
  Area,
  ComposedChart,
  Bar,
} from 'recharts'
import { format } from 'date-fns'
import { SecurityMetrics } from '@/types/security'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Badge } from '@/components/ui/badge'

interface SecurityMetricsChartProps {
  data: SecurityMetrics[]
}

export function SecurityMetricsChart({ data }: SecurityMetricsChartProps) {
  const [selectedMetric, setSelectedMetric] = useState('authentication')

  const chartData = useMemo(() => {
    return data
      .slice(-50) // Show last 50 data points
      .map(metric => ({
        time: format(new Date(metric.timestamp), 'HH:mm:ss'),
        authSuccess: metric.authenticationSuccess,
        authFailure: metric.authenticationFailure,
        mfaUsage: metric.mfaUsage,
        rateLimitTriggers: metric.rateLimitTriggers,
        idorAttempts: metric.idorAttempts,
        tokenReplayAttempts: metric.tokenReplayAttempts,
        totpReplayAttempts: metric.totpReplayAttempts,
        pkceDowngradeAttempts: metric.pkceDowngradeAttempts,
        responseTime: metric.responseTime * 1000, // Convert to ms
        errorRate: metric.errorRate * 100, // Convert to percentage
        activeConnections: metric.activeConnections,
      }))
  }, [data])

  const CustomTooltip = ({ active, payload, label }: any) => {
    if (active && payload && payload.length) {
      return (
        <div className="bg-background border rounded-lg shadow-lg p-3">
          <p className="text-sm font-medium mb-2">{`Time: ${label}`}</p>
          {payload.map((entry: any, index: number) => (
            <p key={index} className="text-sm" style={{ color: entry.color }}>
              {`${entry.name}: ${entry.value.toLocaleString()}`}
            </p>
          ))}
        </div>
      )
    }
    return null
  }

  const renderAuthenticationChart = () => (
    <ResponsiveContainer width="100%" height={400}>
      <ComposedChart data={chartData}>
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
          dataKey="authSuccess"
          stackId="1"
          stroke="#22c55e"
          fill="#22c55e"
          fillOpacity={0.6}
          name="Successful Authentications"
        />
        <Area
          type="monotone"
          dataKey="authFailure"
          stackId="1"
          stroke="#ef4444"
          fill="#ef4444"
          fillOpacity={0.6}
          name="Failed Authentications"
        />
        <Line
          type="monotone"
          dataKey="mfaUsage"
          stroke="#3b82f6"
          strokeWidth={2}
          name="MFA Usage"
          dot={false}
        />
      </ComposedChart>
    </ResponsiveContainer>
  )

  const renderThreatChart = () => (
    <ResponsiveContainer width="100%" height={400}>
      <ComposedChart data={chartData}>
        <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" />
        <XAxis 
          dataKey="time" 
          stroke="hsl(var(--muted-foreground))"
          fontSize={12}
        />
        <YAxis stroke="hsl(var(--muted-foreground))" fontSize={12} />
        <Tooltip content={<CustomTooltip />} />
        <Legend />
        <Bar dataKey="rateLimitTriggers" fill="#f97316" name="Rate Limit Triggers" />
        <Bar dataKey="idorAttempts" fill="#ef4444" name="IDOR Attempts" />
        <Bar dataKey="tokenReplayAttempts" fill="#dc2626" name="Token Replay" />
        <Bar dataKey="totpReplayAttempts" fill="#b91c1c" name="TOTP Replay" />
        <Bar dataKey="pkceDowngradeAttempts" fill="#991b1b" name="PKCE Downgrade" />
      </ComposedChart>
    </ResponsiveContainer>
  )

  const renderPerformanceChart = () => (
    <ResponsiveContainer width="100%" height={400}>
      <ComposedChart data={chartData}>
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
          label={{ value: 'Connections / Error Rate (%)', angle: 90, position: 'insideRight' }}
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
          dataKey="activeConnections"
          stroke="#22c55e"
          strokeWidth={2}
          name="Active Connections"
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
      </ComposedChart>
    </ResponsiveContainer>
  )

  // Calculate summary statistics
  const latestMetric = chartData[chartData.length - 1]
  const authSuccessRate = latestMetric 
    ? (latestMetric.authSuccess / (latestMetric.authSuccess + latestMetric.authFailure)) * 100
    : 0

  const totalThreats = latestMetric 
    ? latestMetric.rateLimitTriggers + 
      latestMetric.idorAttempts + 
      latestMetric.tokenReplayAttempts + 
      latestMetric.totpReplayAttempts + 
      latestMetric.pkceDowngradeAttempts
    : 0

  return (
    <div className="space-y-4">
      {/* Summary Cards */}
      <div className="grid grid-cols-3 gap-4 mb-4">
        <Card className="glass-effect">
          <CardContent className="p-4">
            <div className="text-center">
              <div className="text-2xl font-bold text-green-500">
                {authSuccessRate.toFixed(1)}%
              </div>
              <div className="text-sm text-muted-foreground">Auth Success Rate</div>
            </div>
          </CardContent>
        </Card>
        
        <Card className="glass-effect">
          <CardContent className="p-4">
            <div className="text-center">
              <div className="text-2xl font-bold text-orange-500">
                {totalThreats}
              </div>
              <div className="text-sm text-muted-foreground">Active Threats</div>
            </div>
          </CardContent>
        </Card>
        
        <Card className="glass-effect">
          <CardContent className="p-4">
            <div className="text-center">
              <div className="text-2xl font-bold text-blue-500">
                {latestMetric?.responseTime?.toFixed(0) || 0}ms
              </div>
              <div className="text-sm text-muted-foreground">Response Time</div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Chart Tabs */}
      <Tabs value={selectedMetric} onValueChange={setSelectedMetric}>
        <TabsList className="grid w-full grid-cols-3">
          <TabsTrigger value="authentication">Authentication</TabsTrigger>
          <TabsTrigger value="threats">Threat Detection</TabsTrigger>
          <TabsTrigger value="performance">Performance</TabsTrigger>
        </TabsList>

        <TabsContent value="authentication" className="mt-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center justify-between">
                Authentication Metrics
                <Badge variant="outline">Real-time</Badge>
              </CardTitle>
              <CardDescription>
                Authentication success/failure rates and MFA usage patterns
              </CardDescription>
            </CardHeader>
            <CardContent>
              {renderAuthenticationChart()}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="threats" className="mt-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center justify-between">
                Threat Detection Events
                <Badge variant="outline">Real-time</Badge>
              </CardTitle>
              <CardDescription>
                Security threats and attack patterns detected in real-time
              </CardDescription>
            </CardHeader>
            <CardContent>
              {renderThreatChart()}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="performance" className="mt-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center justify-between">
                System Performance
                <Badge variant="outline">Real-time</Badge>
              </CardTitle>
              <CardDescription>
                Response times, active connections, and error rates
              </CardDescription>
            </CardHeader>
            <CardContent>
              {renderPerformanceChart()}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  )
}