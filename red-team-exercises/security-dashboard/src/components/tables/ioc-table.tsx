import { ThreatEvent } from '@/types/security'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'

interface IOCTableProps {
  threats: ThreatEvent[]
}

export function IOCTable({ threats }: IOCTableProps) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Indicators of Compromise (IOCs)</CardTitle>
        <CardDescription>
          Known malicious indicators extracted from threat events
        </CardDescription>
      </CardHeader>
      <CardContent>
        <div className="text-center py-12 text-muted-foreground">
          <Badge variant="outline">Under Development</Badge>
          <p className="mt-2">IOC tracking and analysis coming soon</p>
        </div>
      </CardContent>
    </Card>
  )
}