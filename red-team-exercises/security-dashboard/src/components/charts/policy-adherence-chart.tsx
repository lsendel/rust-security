import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from 'recharts'

export function PolicyAdherenceChart() {
  const data = [
    { name: 'Compliant', value: 78, color: '#22c55e' },
    { name: 'Violations', value: 15, color: '#ef4444' },
    { name: 'Pending Review', value: 7, color: '#eab308' }
  ]

  return (
    <ResponsiveContainer width="100%" height={300}>
      <PieChart>
        <Pie
          data={data}
          cx="50%"
          cy="50%"
          outerRadius={100}
          dataKey="value"
          label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
        >
          {data.map((entry, index) => (
            <Cell key={`cell-${index}`} fill={entry.color} />
          ))}
        </Pie>
        <Tooltip />
      </PieChart>
    </ResponsiveContainer>
  )
}