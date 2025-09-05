import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'

interface ComplianceControlsMatrixProps {
  frameworkId: string
}

export function ComplianceControlsMatrix({ frameworkId }: ComplianceControlsMatrixProps) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>{frameworkId} Controls Matrix</CardTitle>
        <CardDescription>
          Detailed control assessment and status
        </CardDescription>
      </CardHeader>
      <CardContent>
        <div className="text-center py-12 text-muted-foreground">
          <Badge variant="outline">Under Development</Badge>
          <p className="mt-2">Controls matrix coming soon</p>
        </div>
      </CardContent>
    </Card>
  )
}