import { Badge } from '@/components/ui/badge'
import { SimplePage } from '@/components/layout/simple-page'

export function CloudSecurity() {
  return (
    <SimplePage
      title="Cloud Security"
      description="Multi-cloud security monitoring and compliance"
      cardTitle="Cloud Security Posture"
      cardDescription="Coming soon..."
    >
      <div className="text-center py-12 text-muted-foreground">
        <Badge variant="outline">Under Development</Badge>
      </div>
    </SimplePage>
  )
}