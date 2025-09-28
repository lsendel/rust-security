import { Badge } from '@/components/ui/badge'
import { SimplePage } from '@/components/layout/simple-page'

export function Settings() {
  return (
    <SimplePage
      title="Settings"
      description="Dashboard configuration and user preferences"
      cardTitle="Dashboard Settings"
      cardDescription="Coming soon..."
    >
      <div className="text-center py-12 text-muted-foreground">
        <Badge variant="outline">Under Development</Badge>
      </div>
    </SimplePage>
  )
}