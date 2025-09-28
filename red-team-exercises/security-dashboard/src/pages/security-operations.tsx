import { Badge } from '@/components/ui/badge'
import { SimplePage } from '@/components/layout/simple-page'

export function SecurityOperations() {
  return (
    <SimplePage
      title="Security Operations Center"
      description="Security operations management and incident response workflows"
      cardTitle="SOC Dashboard"
      cardDescription="Coming soon..."
    >
      <div className="text-center py-12 text-muted-foreground">
        <Badge variant="outline">Under Development</Badge>
      </div>
    </SimplePage>
  )
}