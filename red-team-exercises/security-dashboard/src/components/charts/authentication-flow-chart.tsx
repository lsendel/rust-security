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
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar
} from 'recharts'
import { format } from 'date-fns'
import { SecurityMetrics } from '@/types/security'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Badge } from '@/components/ui/badge'

interface AuthenticationFlowChartProps {
  data: SecurityMetrics[]
}

export function AuthenticationFlowChart({ data }: AuthenticationFlowChartProps) {
  const chartData = useMemo(() => {
    return data
      .slice(-30) // Show last 30 data points
      .map(metric => ({
        time: format(new Date(metric.timestamp), 'HH:mm'),
        successCount: metric.authenticationSuccess,
        failureCount: metric.authenticationFailure,
        mfaCount: metric.mfaUsage,
        successRate: metric.authenticationSuccess / (metric.authenticationSuccess + metric.authenticationFailure) * 100,
        mfaRate: metric.mfaUsage / metric.authenticationSuccess * 100
      }))
  }, [data])

  // Calculate summary stats
  const totalAuth = data.reduce((sum, d) => sum + d.authenticationSuccess + d.authenticationFailure, 0)
  const totalSuccess = data.reduce((sum, d) => sum + d.authenticationSuccess, 0)
  const totalMFA = data.reduce((sum, d) => sum + d.mfaUsage, 0)
  const overallSuccessRate = totalAuth > 0 ? (totalSuccess / totalAuth) * 100 : 0
  const mfaAdoptionRate = totalSuccess > 0 ? (totalMFA / totalSuccess) * 100 : 0

  // Pie chart data for authentication methods
  const authMethodData = [
    { name: 'Username/Password', value: 45, color: '#3b82f6' },
    { name: 'MFA (TOTP)', value: 35, color: '#22c55e' },
    { name: 'OAuth/OIDC', value: 15, color: '#f59e0b' },
    { name: 'API Keys', value: 5, color: '#ef4444' }
  ]

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

  return (
    <div className="space-y-4">
      {/* Summary Cards */}
      <div className="grid grid-cols-3 gap-4">
        <Card className="glass-effect">
          <CardContent className="p-4">
            <div className="text-center">
              <div className="text-2xl font-bold text-green-500">
                {overallSuccessRate.toFixed(1)}%
              </div>
              <div className="text-sm text-muted-foreground">Success Rate</div>
            </div>
          </CardContent>
        </Card>
        
        <Card className="glass-effect">
          <CardContent className="p-4">
            <div className="text-center">
              <div className="text-2xl font-bold text-blue-500">
                {mfaAdoptionRate.toFixed(1)}%
              </div>
              <div className="text-sm text-muted-foreground">MFA Adoption</div>
            </div>
          </CardContent>
        </Card>
        
        <Card className="glass-effect">
          <CardContent className="p-4">
            <div className="text-center">
              <div className="text-2xl font-bold text-purple-500">
                {totalAuth.toLocaleString()}
              </div>
              <div className="text-sm text-muted-foreground">Total Attempts</div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Charts */}
      <Tabs defaultValue="timeline" className="space-y-4">
        <TabsList className="grid w-full grid-cols-3">
          <TabsTrigger value="timeline">Timeline</TabsTrigger>
          <TabsTrigger value="methods">Auth Methods</TabsTrigger>
          <TabsTrigger value="patterns">Patterns</TabsTrigger>
        </TabsList>

        <TabsContent value="timeline">
          <Card>
            <CardHeader>
              <CardTitle>Authentication Timeline</CardTitle>
              <CardDescription>
                Success and failure rates over time
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
                  <YAxis stroke="hsl(var(--muted-foreground))" fontSize={12} />
                  <Tooltip content={<CustomTooltip />} />
                  <Legend />
                  <Line
                    type="monotone"
                    dataKey="successCount"
                    stroke="#22c55e"
                    strokeWidth={2}
                    name="Successful Logins"
                    dot={false}
                  />
                  <Line
                    type="monotone"
                    dataKey="failureCount"
                    stroke="#ef4444"
                    strokeWidth={2}
                    name="Failed Logins"
                    dot={false}
                  />
                  <Line
                    type="monotone"
                    dataKey="mfaCount"
                    stroke="#3b82f6"
                    strokeWidth={2}
                    name="MFA Usage"
                    dot={false}
                  />
                </LineChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="methods">
          <Card>
            <CardHeader>
              <CardTitle>Authentication Methods</CardTitle>
              <CardDescription>
                Distribution of authentication methods used
              </CardDescription>
            </CardHeader>
            <CardContent>
              <ResponsiveContainer width="100%" height={300}>
                <PieChart>
                  <Pie
                    data={authMethodData}
                    cx="50%"
                    cy="50%"
                    outerRadius={100}
                    dataKey="value"
                    label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                  >
                    {authMethodData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip />
                </PieChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="patterns">
          <Card>
            <CardHeader>
              <CardTitle>Authentication Patterns</CardTitle>
              <CardDescription>
                Success rates and security indicators
              </CardDescription>
            </CardHeader>
            <CardContent>
              <ResponsiveContainer width="100%" height={300}>
                <BarChart data={chartData.slice(-10)}>
                  <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" />
                  <XAxis 
                    dataKey="time" 
                    stroke="hsl(var(--muted-foreground))"
                    fontSize={12}
                  />
                  <YAxis stroke="hsl(var(--muted-foreground))" fontSize={12} />
                  <Tooltip content={<CustomTooltip />} />
                  <Legend />
                  <Bar dataKey="successRate" fill="#22c55e" name="Success Rate %" />
                  <Bar dataKey="mfaRate" fill="#3b82f6" name="MFA Rate %" />
                </BarChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  )
}