import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Progress } from '@/components/ui/progress'
import { CheckCircle, AlertCircle, XCircle, Clock } from 'lucide-react'

export function ComplianceOverview() {
  const frameworks = [
    {
      name: 'SOC 2 Type II',
      score: 94,
      status: 'compliant',
      lastAudit: '2024-01-15',
      nextAudit: '2024-07-15',
      controls: { total: 147, passed: 138, failed: 2, partial: 7 }
    },
    {
      name: 'PCI DSS',
      score: 87,
      status: 'partial',
      lastAudit: '2024-02-01',
      nextAudit: '2025-02-01',
      controls: { total: 375, passed: 326, failed: 11, partial: 38 }
    },
    {
      name: 'GDPR',
      score: 91,
      status: 'compliant',
      lastAudit: '2024-02-20',
      nextAudit: '2024-08-20',
      controls: { total: 89, passed: 81, failed: 2, partial: 6 }
    },
    {
      name: 'ISO 27001',
      score: 89,
      status: 'compliant',
      lastAudit: '2024-01-30',
      nextAudit: '2025-01-30',
      controls: { total: 114, passed: 101, failed: 3, partial: 10 }
    }
  ]

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'compliant':
        return <CheckCircle className="h-4 w-4 text-green-500" />
      case 'partial':
        return <AlertCircle className="h-4 w-4 text-yellow-500" />
      case 'non-compliant':
        return <XCircle className="h-4 w-4 text-red-500" />
      default:
        return <Clock className="h-4 w-4 text-gray-500" />
    }
  }

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'compliant':
        return 'text-green-500'
      case 'partial':
        return 'text-yellow-500'
      case 'non-compliant':
        return 'text-red-500'
      default:
        return 'text-gray-500'
    }
  }

  return (
    <div className="space-y-6">
      {/* Overall Summary */}
      <div className="grid gap-4 md:grid-cols-4">
        <Card className="glass-effect">
          <CardContent className="p-4">
            <div className="text-center">
              <div className="text-2xl font-bold text-green-500">90.3%</div>
              <div className="text-sm text-muted-foreground">Overall Compliance</div>
            </div>
          </CardContent>
        </Card>
        
        <Card className="glass-effect">
          <CardContent className="p-4">
            <div className="text-center">
              <div className="text-2xl font-bold text-blue-500">3/4</div>
              <div className="text-sm text-muted-foreground">Compliant Frameworks</div>
            </div>
          </CardContent>
        </Card>
        
        <Card className="glass-effect">
          <CardContent className="p-4">
            <div className="text-center">
              <div className="text-2xl font-bold text-purple-500">725</div>
              <div className="text-sm text-muted-foreground">Total Controls</div>
            </div>
          </CardContent>
        </Card>
        
        <Card className="glass-effect">
          <CardContent className="p-4">
            <div className="text-center">
              <div className="text-2xl font-bold text-orange-500">18</div>
              <div className="text-sm text-muted-foreground">Action Items</div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Framework Details */}
      <div className="grid gap-4 md:grid-cols-2">
        {frameworks.map((framework) => (
          <Card key={framework.name}>
            <CardHeader>
              <div className="flex items-center justify-between">
                <CardTitle className="text-lg">{framework.name}</CardTitle>
                <div className="flex items-center gap-2">
                  {getStatusIcon(framework.status)}
                  <Badge 
                    variant={framework.status === 'compliant' ? 'default' : 'destructive'}
                  >
                    {framework.status}
                  </Badge>
                </div>
              </div>
              <CardDescription>
                Last audit: {framework.lastAudit} • Next audit: {framework.nextAudit}
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="text-center">
                <div className={`text-3xl font-bold ${getStatusColor(framework.status)}`}>
                  {framework.score}%
                </div>
                <Progress value={framework.score} className="mt-2" />
              </div>
              
              <div className="grid grid-cols-4 gap-2 text-center text-sm">
                <div>
                  <div className="text-lg font-semibold text-green-500">
                    {framework.controls.passed}
                  </div>
                  <div className="text-muted-foreground">Passed</div>
                </div>
                <div>
                  <div className="text-lg font-semibold text-yellow-500">
                    {framework.controls.partial}
                  </div>
                  <div className="text-muted-foreground">Partial</div>
                </div>
                <div>
                  <div className="text-lg font-semibold text-red-500">
                    {framework.controls.failed}
                  </div>
                  <div className="text-muted-foreground">Failed</div>
                </div>
                <div>
                  <div className="text-lg font-semibold">
                    {framework.controls.total}
                  </div>
                  <div className="text-muted-foreground">Total</div>
                </div>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Recent Compliance Events */}
      <Card>
        <CardHeader>
          <CardTitle>Recent Compliance Activities</CardTitle>
          <CardDescription>
            Latest compliance-related events and updates
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-3">
            {[
              {
                title: 'SOC 2 Control Update',
                description: 'Updated access control procedures for user management',
                timestamp: '2 hours ago',
                type: 'improvement',
                framework: 'SOC 2'
              },
              {
                title: 'PCI DSS Remediation',
                description: 'Fixed vulnerability in payment processing module',
                timestamp: '1 day ago',
                type: 'remediation',
                framework: 'PCI DSS'
              },
              {
                title: 'GDPR Data Processing Audit',
                description: 'Completed quarterly data processing review',
                timestamp: '3 days ago',
                type: 'audit',
                framework: 'GDPR'
              },
              {
                title: 'ISO 27001 Policy Review',
                description: 'Annual security policy review and update',
                timestamp: '1 week ago',
                type: 'review',
                framework: 'ISO 27001'
              }
            ].map((event, index) => (
              <div key={index} className="flex items-center justify-between p-3 border rounded-lg">
                <div className="flex-1">
                  <div className="flex items-center gap-2 mb-1">
                    <Badge variant="outline">{event.framework}</Badge>
                    <span className="font-medium">{event.title}</span>
                  </div>
                  <p className="text-sm text-muted-foreground">
                    {event.description}
                  </p>
                </div>
                <div className="text-right">
                  <div className="text-xs text-muted-foreground">
                    {event.timestamp}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
    </div>
  )
}