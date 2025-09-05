import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'

export function SecurityOperations() {
  return (
    <div className="flex-1 space-y-6 p-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Security Operations Center</h1>
        <p className="text-muted-foreground">
          Security operations management and incident response workflows
        </p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>SOC Dashboard</CardTitle>
          <CardDescription>Coming soon...</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="text-center py-12 text-muted-foreground">
            <Badge variant="outline">Under Development</Badge>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}