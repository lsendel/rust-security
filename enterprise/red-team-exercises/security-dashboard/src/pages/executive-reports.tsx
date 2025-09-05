import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'

export function ExecutiveReports() {
  return (
    <div className="flex-1 space-y-6 p-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Executive Reports</h1>
        <p className="text-muted-foreground">
          High-level security metrics and executive dashboards
        </p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Executive Security Dashboard</CardTitle>
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