import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'

export function AuditTrailTable() {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Audit Trail</CardTitle>
        <CardDescription>
          System audit logs and user activity tracking
        </CardDescription>
      </CardHeader>
      <CardContent>
        <div className="text-center py-12 text-muted-foreground">
          <Badge variant="outline">Under Development</Badge>
          <p className="mt-2">Audit trail visualization coming soon</p>
        </div>
      </CardContent>
    </Card>
  )
}