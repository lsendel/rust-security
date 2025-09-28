import { Badge } from '@/components/ui/badge'
import { SimplePage } from '@/components/layout/simple-page'

export function AuthenticationFlow() {
  return (
    <SimplePage
      title="Authentication Flow"
      description="Detailed authentication flow monitoring and analysis"
      cardTitle="Authentication Flow Analysis"
      cardDescription="Coming soon..."
    >
      <div className="text-center py-12 text-muted-foreground">
        <Badge variant="outline">Under Development</Badge>
      </div>
    </SimplePage>
  )
}