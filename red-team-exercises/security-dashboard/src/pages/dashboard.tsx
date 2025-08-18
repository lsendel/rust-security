import { useState, useEffect } from 'react'
import { motion } from 'framer-motion'
import { Shield, AlertTriangle, Activity, Users, Lock, Globe, BarChart3, Zap } from 'lucide-react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Badge } from '@/components/ui/badge'
import { SecurityMetricsChart } from '@/components/charts/security-metrics-chart'
import { ThreatMapVisualization } from '@/components/charts/threat-map'
import { AuthenticationFlowChart } from '@/components/charts/authentication-flow-chart'
import { RealTimeAlerts } from '@/components/alerts/real-time-alerts'
import { SecurityScoreCard } from '@/components/cards/security-score-card'
import { ComplianceOverview } from '@/components/compliance/compliance-overview'
import { PerformanceMetrics } from '@/components/metrics/performance-metrics'
import { useSecurityMetrics, useThreatEvents, useSecurityAlerts } from '@/hooks/use-websocket'
import { useQuery } from '@tanstack/react-query'
import { SecurityMetrics } from '@/types/security'
import { formatNumber, formatPercentage } from '@/lib/utils'

export function Dashboard() {
  const securityMetrics = useSecurityMetrics()
  const threatEvents = useThreatEvents()
  const securityAlerts = useSecurityAlerts()
  const [selectedTimeRange, setSelectedTimeRange] = useState('1h')

  // Fetch initial dashboard data
  const { data: dashboardOverview } = useQuery({
    queryKey: ['dashboard-overview', selectedTimeRange],
    queryFn: async () => {
      const response = await fetch(`/api/dashboard/overview?timeRange=${selectedTimeRange}`)
      return response.json()
    },
    refetchInterval: 30000, // Refresh every 30 seconds
  })

  // Calculate current metrics
  const currentMetrics = securityMetrics[0]
  const totalThreats = threatEvents.length
  const criticalAlerts = securityAlerts.filter(alert => alert.severity === 'critical').length
  const authSuccessRate = currentMetrics 
    ? currentMetrics.authenticationSuccess / (currentMetrics.authenticationSuccess + currentMetrics.authenticationFailure) 
    : 0

  const containerVariants = {
    hidden: { opacity: 0 },
    visible: {
      opacity: 1,
      transition: {
        staggerChildren: 0.1
      }
    }
  }

  const itemVariants = {
    hidden: { y: 20, opacity: 0 },
    visible: {
      y: 0,
      opacity: 1,
      transition: {
        type: "spring",
        stiffness: 100
      }
    }
  }

  return (
    <div className="flex-1 space-y-6 p-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Security Dashboard</h1>
          <p className="text-muted-foreground">
            Real-time security monitoring and threat detection
          </p>
        </div>
        <div className="flex items-center space-x-2">
          <Badge 
            variant={criticalAlerts > 0 ? "destructive" : "secondary"}
            className="animate-pulse"
          >
            {criticalAlerts} Critical Alerts
          </Badge>
          <select 
            value={selectedTimeRange}
            onChange={(e) => setSelectedTimeRange(e.target.value)}
            className="rounded-md border border-input bg-background px-3 py-2 text-sm"
          >
            <option value="15m">Last 15 minutes</option>
            <option value="1h">Last hour</option>
            <option value="6h">Last 6 hours</option>
            <option value="24h">Last 24 hours</option>
            <option value="7d">Last 7 days</option>
          </select>
        </div>
      </div>

      {/* Key Metrics Cards */}
      <motion.div
        variants={containerVariants}
        initial="hidden"
        animate="visible"
        className="grid gap-4 md:grid-cols-2 lg:grid-cols-4"
      >
        <motion.div variants={itemVariants}>
          <Card className="glass-effect">
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Authentication Success Rate</CardTitle>
              <Shield className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-green-500">
                {formatPercentage(authSuccessRate)}
              </div>
              <p className="text-xs text-muted-foreground">
                +2.1% from last hour
              </p>
            </CardContent>
          </Card>
        </motion.div>

        <motion.div variants={itemVariants}>
          <Card className="glass-effect">
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Active Threats</CardTitle>
              <AlertTriangle className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-orange-500">
                {formatNumber(totalThreats)}
              </div>
              <p className="text-xs text-muted-foreground">
                -5 from last hour
              </p>
            </CardContent>
          </Card>
        </motion.div>

        <motion.div variants={itemVariants}>
          <Card className="glass-effect">
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">System Performance</CardTitle>
              <Activity className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-blue-500">
                {currentMetrics ? `${Math.round(currentMetrics.responseTime * 1000)}ms` : 'N/A'}
              </div>
              <p className="text-xs text-muted-foreground">
                Response time (P95)
              </p>
            </CardContent>
          </Card>
        </motion.div>

        <motion.div variants={itemVariants}>
          <Card className="glass-effect">
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Active Sessions</CardTitle>
              <Users className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-purple-500">
                {currentMetrics ? formatNumber(currentMetrics.activeConnections) : 'N/A'}
              </div>
              <p className="text-xs text-muted-foreground">
                +12% from last hour
              </p>
            </CardContent>
          </Card>
        </motion.div>
      </motion.div>

      {/* Main Content Tabs */}
      <Tabs defaultValue="overview" className="space-y-4">
        <TabsList className="grid w-full grid-cols-5">
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="threats">Threat Detection</TabsTrigger>
          <TabsTrigger value="authentication">Authentication</TabsTrigger>
          <TabsTrigger value="performance">Performance</TabsTrigger>
          <TabsTrigger value="compliance">Compliance</TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="space-y-4">
          <motion.div
            variants={containerVariants}
            initial="hidden"
            animate="visible"
            className="grid gap-4 md:grid-cols-2 lg:grid-cols-3"
          >
            <motion.div variants={itemVariants} className="md:col-span-2">
              <Card>
                <CardHeader>
                  <CardTitle>Security Metrics Timeline</CardTitle>
                  <CardDescription>
                    Real-time security events and system performance
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <SecurityMetricsChart data={securityMetrics} />
                </CardContent>
              </Card>
            </motion.div>

            <motion.div variants={itemVariants}>
              <SecurityScoreCard />
            </motion.div>

            <motion.div variants={itemVariants} className="lg:col-span-2">
              <Card>
                <CardHeader>
                  <CardTitle>Global Threat Map</CardTitle>
                  <CardDescription>
                    Geographic distribution of security threats
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <ThreatMapVisualization threats={threatEvents} />
                </CardContent>
              </Card>
            </motion.div>

            <motion.div variants={itemVariants}>
              <RealTimeAlerts alerts={securityAlerts} />
            </motion.div>
          </motion.div>
        </TabsContent>

        <TabsContent value="threats" className="space-y-4">
          <motion.div
            variants={containerVariants}
            initial="hidden"
            animate="visible"
            className="grid gap-4 md:grid-cols-2"
          >
            <motion.div variants={itemVariants}>
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <AlertTriangle className="h-5 w-5 text-orange-500" />
                    Threat Detection Summary
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    <div className="flex justify-between items-center">
                      <span>Rate Limiting Triggers</span>
                      <Badge variant="outline">
                        {currentMetrics?.rateLimitTriggers || 0}
                      </Badge>
                    </div>
                    <div className="flex justify-between items-center">
                      <span>IDOR Attempts</span>
                      <Badge variant="outline">
                        {currentMetrics?.idorAttempts || 0}
                      </Badge>
                    </div>
                    <div className="flex justify-between items-center">
                      <span>Token Replay Attempts</span>
                      <Badge variant="outline">
                        {currentMetrics?.tokenReplayAttempts || 0}
                      </Badge>
                    </div>
                    <div className="flex justify-between items-center">
                      <span>TOTP Replay Attempts</span>
                      <Badge variant="outline">
                        {currentMetrics?.totpReplayAttempts || 0}
                      </Badge>
                    </div>
                    <div className="flex justify-between items-center">
                      <span>PKCE Downgrade Attempts</span>
                      <Badge variant="outline">
                        {currentMetrics?.pkceDowngradeAttempts || 0}
                      </Badge>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </motion.div>

            <motion.div variants={itemVariants}>
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Globe className="h-5 w-5 text-blue-500" />
                    Threat Intelligence
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    <div className="text-sm text-muted-foreground">
                      Latest threat indicators and attack patterns
                    </div>
                    {threatEvents.slice(0, 5).map((threat) => (
                      <div key={threat.id} className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <Badge 
                            variant={threat.severity === 'critical' ? 'destructive' : 'outline'}
                          >
                            {threat.severity}
                          </Badge>
                          <span className="text-sm">{threat.type}</span>
                        </div>
                        <span className="text-xs text-muted-foreground">
                          {threat.sourceIp}
                        </span>
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>
            </motion.div>
          </motion.div>
        </TabsContent>

        <TabsContent value="authentication" className="space-y-4">
          <motion.div variants={itemVariants}>
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Lock className="h-5 w-5 text-green-500" />
                  Authentication Flow Analysis
                </CardTitle>
                <CardDescription>
                  Success rates, MFA usage, and failure patterns
                </CardDescription>
              </CardHeader>
              <CardContent>
                <AuthenticationFlowChart data={securityMetrics} />
              </CardContent>
            </Card>
          </motion.div>
        </TabsContent>

        <TabsContent value="performance" className="space-y-4">
          <motion.div variants={itemVariants}>
            <PerformanceMetrics metrics={securityMetrics} />
          </motion.div>
        </TabsContent>

        <TabsContent value="compliance" className="space-y-4">
          <motion.div variants={itemVariants}>
            <ComplianceOverview />
          </motion.div>
        </TabsContent>
      </Tabs>
    </div>
  )
}