import { useMemo } from 'react'
import {
  ScatterChart,
  Scatter,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Cell
} from 'recharts'
import { ThreatEvent } from '@/types/security'

interface RiskScoreMatrixProps {
  threats: ThreatEvent[]
}

export function RiskScoreMatrix({ threats }: RiskScoreMatrixProps) {
  const chartData = useMemo(() => {
    return threats.map(threat => ({
      riskScore: threat.riskScore,
      frequency: Math.random() * 10 + 1, // Mock frequency data
      severity: threat.severity,
      type: threat.type,
      id: threat.id
    }))
  }, [threats])

  const getColor = (severity: string) => {
    switch (severity) {
      case 'critical': return '#ef4444'
      case 'high': return '#f97316'
      case 'medium': return '#eab308'
      case 'low': return '#22c55e'
      default: return '#6b7280'
    }
  }

  const CustomTooltip = ({ active, payload }: any) => {
    if (active && payload && payload.length) {
      const data = payload[0].payload
      return (
        <div className="bg-background border rounded-lg shadow-lg p-3">
          <p className="text-sm font-medium mb-1">{data.type}</p>
          <p className="text-sm">Risk Score: {data.riskScore}</p>
          <p className="text-sm">Frequency: {data.frequency.toFixed(1)}</p>
          <p className="text-sm">Severity: {data.severity}</p>
        </div>
      )
    }
    return null
  }

  return (
    <ResponsiveContainer width="100%" height={300}>
      <ScatterChart>
        <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" />
        <XAxis 
          type="number"
          dataKey="riskScore"
          domain={[0, 100]}
          stroke="hsl(var(--muted-foreground))"
          fontSize={12}
          label={{ value: 'Risk Score', position: 'insideBottom', offset: -5 }}
        />
        <YAxis 
          type="number"
          dataKey="frequency"
          domain={[0, 10]}
          stroke="hsl(var(--muted-foreground))"
          fontSize={12}
          label={{ value: 'Frequency', angle: -90, position: 'insideLeft' }}
        />
        <Tooltip content={<CustomTooltip />} />
        <Scatter data={chartData}>
          {chartData.map((entry, index) => (
            <Cell key={`cell-${index}`} fill={getColor(entry.severity)} />
          ))}
        </Scatter>
      </ScatterChart>
    </ResponsiveContainer>
  )
}