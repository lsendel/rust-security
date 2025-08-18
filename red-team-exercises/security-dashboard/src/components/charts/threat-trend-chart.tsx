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
import { format, subHours } from 'date-fns'
import { ThreatEvent } from '@/types/security'

interface ThreatTrendChartProps {
  threats: ThreatEvent[]
}

export function ThreatTrendChart({ threats }: ThreatTrendChartProps) {
  const chartData = useMemo(() => {
    // Group threats by hour for the last 24 hours
    const hourlyData = new Map()
    const now = new Date()
    
    // Initialize 24 hours of data
    for (let i = 23; i >= 0; i--) {
      const hour = subHours(now, i)
      const key = format(hour, 'HH:00')
      hourlyData.set(key, {
        time: key,
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        total: 0
      })
    }

    // Aggregate threats by hour and severity
    threats.forEach(threat => {
      const threatTime = new Date(threat.timestamp)
      const key = format(threatTime, 'HH:00')
      
      if (hourlyData.has(key)) {
        const data = hourlyData.get(key)
        data[threat.severity]++
        data.total++
      }
    })

    return Array.from(hourlyData.values())
  }, [threats])

  const CustomTooltip = ({ active, payload, label }: any) => {
    if (active && payload && payload.length) {
      return (
        <div className="bg-background border rounded-lg shadow-lg p-3">
          <p className="text-sm font-medium mb-2">{`Time: ${label}`}</p>
          {payload.map((entry: any, index: number) => (
            <p key={index} className="text-sm" style={{ color: entry.color }}>
              {`${entry.name}: ${entry.value}`}
            </p>
          ))}
        </div>
      )
    }
    return null
  }

  return (
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
          dataKey="critical"
          stackId="1"
          stroke="#ef4444"
          fill="#ef4444"
          fillOpacity={0.8}
          name="Critical"
        />
        <Area
          type="monotone"
          dataKey="high"
          stackId="1"
          stroke="#f97316"
          fill="#f97316"
          fillOpacity={0.6}
          name="High"
        />
        <Area
          type="monotone"
          dataKey="medium"
          stackId="1"
          stroke="#eab308"
          fill="#eab308"
          fillOpacity={0.4}
          name="Medium"
        />
        <Area
          type="monotone"
          dataKey="low"
          stackId="1"
          stroke="#22c55e"
          fill="#22c55e"
          fillOpacity={0.2}
          name="Low"
        />
      </AreaChart>
    </ResponsiveContainer>
  )
}