import { Badge } from '@/components/ui/badge'
import { SimplePage } from '@/components/layout/simple-page'

export function IncidentResponse() {
  return (
    <SimplePage
      title="Incident Response"
      description="Incident management and response coordination"
      cardTitle="Incident Response Management"
      cardDescription="Coming soon..."
    >
      <div className="text-center py-12 text-muted-foreground">
        <Badge variant="outline">Under Development</Badge>
      </div>
    </SimplePage>
  )
}