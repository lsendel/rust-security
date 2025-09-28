import { Badge } from '@/components/ui/badge'
import { SimplePage } from '@/components/layout/simple-page'

export function AnalyticsInsights() {
  return (
    <SimplePage
      title="Analytics & ML Insights"
      description="Advanced analytics and machine learning powered security insights"
      cardTitle="ML Security Analytics"
      cardDescription="Coming soon..."
    >
      <div className="text-center py-12 text-muted-foreground">
        <Badge variant="outline">Under Development</Badge>
      </div>
    </SimplePage>
  )
}