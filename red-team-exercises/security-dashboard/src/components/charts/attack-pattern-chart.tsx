import { useMemo } from 'react'
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell
} from 'recharts'
import { ThreatEvent } from '@/types/security'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'

interface AttackPatternChartProps {
  threats: ThreatEvent[]
}

export function AttackPatternChart({ threats }: AttackPatternChartProps) {
  const attackTypeData = useMemo(() => {
    const typeCounts = threats.reduce((acc, threat) => {
      acc[threat.type] = (acc[threat.type] || 0) + 1
      return acc
    }, {} as Record<string, number>)

    return Object.entries(typeCounts)
      .map(([type, count]) => ({ type, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 10) // Top 10 attack types
  }, [threats])

  const severityData = useMemo(() => {
    const severityCounts = threats.reduce((acc, threat) => {
      acc[threat.severity] = (acc[threat.severity] || 0) + 1
      return acc
    }, {} as Record<string, number>)

    return Object.entries(severityCounts).map(([severity, count]) => ({
      severity,
      count,
      color: getSeverityColor(severity)
    }))
  }, [threats])

  const timePatternData = useMemo(() => {
    const hourCounts = new Array(24).fill(0)
    
    threats.forEach(threat => {
      const hour = new Date(threat.timestamp).getHours()
      hourCounts[hour]++
    })

    return hourCounts.map((count, hour) => ({
      hour: `${hour}:00`,
      count
    }))
  }, [threats])

  function getSeverityColor(severity: string) {
    switch (severity) {
      case 'critical': return '#ef4444'
      case 'high': return '#f97316'
      case 'medium': return '#eab308'
      case 'low': return '#22c55e'
      default: return '#6b7280'
    }
  }

  const CustomTooltip = ({ active, payload, label }: any) => {
    if (active && payload && payload.length) {
      return (
        <div className="bg-background border rounded-lg shadow-lg p-3">
          <p className="text-sm font-medium mb-2">{label}</p>
          {payload.map((entry: any, index: number) => (
            <p key={index} className="text-sm" style={{ color: entry.color }}>
              {`${entry.name || entry.dataKey}: ${entry.value}`}
            </p>
          ))}
        </div>
      )
    }
    return null
  }

  return (
    <div className="space-y-4">
      <Tabs defaultValue="attack-types" className="space-y-4">
        <TabsList className="grid w-full grid-cols-3">
          <TabsTrigger value="attack-types">Attack Types</TabsTrigger>
          <TabsTrigger value="severity">Severity Distribution</TabsTrigger>
          <TabsTrigger value="time-patterns">Time Patterns</TabsTrigger>
        </TabsList>

        <TabsContent value="attack-types">
          <Card>
            <CardHeader>
              <CardTitle>Top Attack Types</CardTitle>
              <CardDescription>
                Most frequent attack vectors detected
              </CardDescription>
            </CardHeader>
            <CardContent>
              <ResponsiveContainer width="100%" height={400}>
                <BarChart data={attackTypeData} layout="horizontal">
                  <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" />
                  <XAxis type="number" stroke="hsl(var(--muted-foreground))" fontSize={12} />
                  <YAxis 
                    type="category" 
                    dataKey="type" 
                    stroke="hsl(var(--muted-foreground))" 
                    fontSize={12}
                    width={120}
                  />
                  <Tooltip content={<CustomTooltip />} />
                  <Bar dataKey="count" fill="#3b82f6" name="Occurrences" />
                </BarChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="severity">
          <Card>
            <CardHeader>
              <CardTitle>Threat Severity Distribution</CardTitle>
              <CardDescription>
                Breakdown of threats by severity level
              </CardDescription>
            </CardHeader>
            <CardContent>
              <ResponsiveContainer width="100%" height={400}>
                <PieChart>
                  <Pie
                    data={severityData}
                    cx="50%"
                    cy="50%"
                    outerRadius={120}
                    dataKey="count"
                    nameKey="severity"
                    label={({ severity, percent }) => 
                      `${severity} (${(percent * 100).toFixed(1)}%)`
                    }
                  >
                    {severityData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip content={<CustomTooltip />} />
                </PieChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="time-patterns">
          <Card>
            <CardHeader>
              <CardTitle>Attack Time Patterns</CardTitle>
              <CardDescription>
                Hourly distribution of attack attempts
              </CardDescription>
            </CardHeader>
            <CardContent>
              <ResponsiveContainer width="100%" height={400}>
                <BarChart data={timePatternData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" />
                  <XAxis 
                    dataKey="hour" 
                    stroke="hsl(var(--muted-foreground))" 
                    fontSize={12}
                  />
                  <YAxis stroke="hsl(var(--muted-foreground))" fontSize={12} />
                  <Tooltip content={<CustomTooltip />} />
                  <Bar dataKey="count" fill="#8b5cf6" name="Attack Count" />
                </BarChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  )
}