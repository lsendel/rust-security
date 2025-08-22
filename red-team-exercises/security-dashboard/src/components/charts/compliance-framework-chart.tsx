import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts'

interface ComplianceFrameworkChartProps {
  frameworks: any[]
}

export function ComplianceFrameworkChart({ frameworks: _frameworks }: ComplianceFrameworkChartProps) {
  // Mock time series data for compliance scores
  const chartData = [
    { date: '2024-01-01', 'SOC 2': 92, 'PCI DSS': 85, 'GDPR': 89, 'ISO 27001': 87 },
    { date: '2024-01-15', 'SOC 2': 93, 'PCI DSS': 86, 'GDPR': 90, 'ISO 27001': 88 },
    { date: '2024-02-01', 'SOC 2': 94, 'PCI DSS': 87, 'GDPR': 91, 'ISO 27001': 89 },
  ]

  return (
    <ResponsiveContainer width="100%" height={300}>
      <LineChart data={chartData}>
        <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" />
        <XAxis dataKey="date" stroke="hsl(var(--muted-foreground))" fontSize={12} />
        <YAxis stroke="hsl(var(--muted-foreground))" fontSize={12} />
        <Tooltip />
        <Legend />
        <Line type="monotone" dataKey="SOC 2" stroke="#3b82f6" strokeWidth={2} />
        <Line type="monotone" dataKey="PCI DSS" stroke="#ef4444" strokeWidth={2} />
        <Line type="monotone" dataKey="GDPR" stroke="#22c55e" strokeWidth={2} />
        <Line type="monotone" dataKey="ISO 27001" stroke="#8b5cf6" strokeWidth={2} />
      </LineChart>
    </ResponsiveContainer>
  )
}