import { ThreatEvent } from '@/types/security'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'

interface ThreatActorProfilesProps {
  threats: ThreatEvent[]
}

export function ThreatActorProfiles({ threats }: ThreatActorProfilesProps) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Threat Actor Profiles</CardTitle>
        <CardDescription>
          Known threat actors and their attack patterns
        </CardDescription>
      </CardHeader>
      <CardContent>
        <div className="text-center py-12 text-muted-foreground">
          <Badge variant="outline">Under Development</Badge>
          <p className="mt-2">Threat actor attribution coming soon</p>
        </div>
      </CardContent>
    </Card>
  )
}