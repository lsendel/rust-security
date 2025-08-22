import { useState, useMemo } from 'react'
import { motion } from 'framer-motion'
import { 
  Shield, 
  AlertCircle, 
  FileText, 
  Download,
  Calendar,
  TrendingUp
} from 'lucide-react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Progress } from '@/components/ui/progress'
import { ComplianceFrameworkChart } from '@/components/charts/compliance-framework-chart'
import { AuditTrailTable } from '@/components/tables/audit-trail-table'
import { ComplianceControlsMatrix } from '@/components/compliance/compliance-controls-matrix'
import { PolicyAdherenceChart } from '@/components/charts/policy-adherence-chart'
import { DataProtectionMetrics } from '@/components/metrics/data-protection-metrics'
import { useQuery } from '@tanstack/react-query'
import { formatPercentage, getComplianceStatus } from '@/lib/utils'

interface ComplianceFramework {
  id: string
  name: string
  version: string
  overallScore: number
  lastAssessment: number
  nextAssessment: number
  status: 'compliant' | 'partial' | 'non-compliant'
  controls: {
    total: number
    compliant: number
    partial: number
    nonCompliant: number
  }
}

export function ComplianceAudit() {
  const [selectedFramework, setSelectedFramework] = useState('SOC2')
  const [selectedTimeRange, _setSelectedTimeRange] = useState('30d')

  // Fetch compliance data
  const { data: _complianceData, isLoading: _isLoading } = useQuery({
    queryKey: ['compliance-data', selectedTimeRange],
    queryFn: async () => {
      const response = await fetch(`/api/compliance?timeRange=${selectedTimeRange}`)
      return response.json()
    },
    refetchInterval: 300000, // Refresh every 5 minutes
  })

  // Mock compliance frameworks data
  const frameworks: ComplianceFramework[] = useMemo(() => [
    {
      id: 'SOC2',
      name: 'SOC 2 Type II',
      version: '2017',
      overallScore: 94,
      lastAssessment: Date.now() - 7 * 24 * 60 * 60 * 1000,
      nextAssessment: Date.now() + 85 * 24 * 60 * 60 * 1000,
      status: 'compliant',
      controls: { total: 147, compliant: 138, partial: 7, nonCompliant: 2 }
    },
    {
      id: 'PCI-DSS',
      name: 'PCI DSS',
      version: '4.0',
      overallScore: 87,
      lastAssessment: Date.now() - 14 * 24 * 60 * 60 * 1000,
      nextAssessment: Date.now() + 351 * 24 * 60 * 60 * 1000,
      status: 'partial',
      controls: { total: 375, compliant: 326, partial: 38, nonCompliant: 11 }
    },
    {
      id: 'GDPR',
      name: 'GDPR',
      version: '2018',
      overallScore: 91,
      lastAssessment: Date.now() - 3 * 24 * 60 * 60 * 1000,
      nextAssessment: Date.now() + 27 * 24 * 60 * 60 * 1000,
      status: 'compliant',
      controls: { total: 89, compliant: 81, partial: 6, nonCompliant: 2 }
    },
    {
      id: 'ISO27001',
      name: 'ISO 27001',
      version: '2022',
      overallScore: 89,
      lastAssessment: Date.now() - 21 * 24 * 60 * 60 * 1000,
      nextAssessment: Date.now() + 344 * 24 * 60 * 60 * 1000,
      status: 'compliant',
      controls: { total: 114, compliant: 101, partial: 10, nonCompliant: 3 }
    }
  ], [])

  const selectedFrameworkData = frameworks.find(f => f.id === selectedFramework)

  // Calculate aggregate metrics
  const aggregateMetrics = useMemo(() => {
    const totalControls = frameworks.reduce((sum, f) => sum + f.controls.total, 0)
    const compliantControls = frameworks.reduce((sum, f) => sum + f.controls.compliant, 0)
    const avgScore = frameworks.reduce((sum, f) => sum + f.overallScore, 0) / frameworks.length
    const compliantFrameworks = frameworks.filter(f => f.status === 'compliant').length
    
    return {
      totalControls,
      compliantControls,
      avgScore,
      compliantFrameworks,
      complianceRate: (compliantControls / totalControls) * 100
    }
  }, [frameworks])

  const containerVariants = {
    hidden: { opacity: 0 },
    visible: {
      opacity: 1,
      transition: { staggerChildren: 0.1 }
    }
  }

  const itemVariants = {
    hidden: { y: 20, opacity: 0 },
    visible: {
      y: 0,
      opacity: 1,
      transition: { type: "spring", stiffness: 100 }
    }
  }

  return (
    <div className="flex-1 space-y-6 p-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Compliance & Audit</h1>
          <p className="text-muted-foreground">
            Regulatory compliance monitoring and audit trail management
          </p>
        </div>
        <div className="flex items-center space-x-2">
          <Button variant="outline">
            <Calendar className="h-4 w-4 mr-2" />
            Schedule Assessment
          </Button>
          <Button variant="outline">
            <Download className="h-4 w-4 mr-2" />
            Generate Report
          </Button>
        </div>
      </div>

      {/* Key Metrics */}
      <motion.div
        variants={containerVariants}
        initial="hidden"
        animate="visible"
        className="grid gap-4 md:grid-cols-2 lg:grid-cols-4"
      >
        <motion.div variants={itemVariants}>
          <Card className="glass-effect">
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Overall Compliance</CardTitle>
              <Shield className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-green-500">
                {formatPercentage(aggregateMetrics.complianceRate / 100)}
              </div>
              <p className="text-xs text-muted-foreground">
                {aggregateMetrics.compliantControls} of {aggregateMetrics.totalControls} controls
              </p>
              <Progress value={aggregateMetrics.complianceRate} className="mt-2" />
            </CardContent>
          </Card>
        </motion.div>

        <motion.div variants={itemVariants}>
          <Card className="glass-effect">
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Frameworks</CardTitle>
              <FileText className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-blue-500">
                {aggregateMetrics.compliantFrameworks}/{frameworks.length}
              </div>
              <p className="text-xs text-muted-foreground">
                Compliant frameworks
              </p>
            </CardContent>
          </Card>
        </motion.div>

        <motion.div variants={itemVariants}>
          <Card className="glass-effect">
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Average Score</CardTitle>
              <TrendingUp className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-purple-500">
                {aggregateMetrics.avgScore.toFixed(0)}%
              </div>
              <p className="text-xs text-muted-foreground">
                Across all frameworks
              </p>
            </CardContent>
          </Card>
        </motion.div>

        <motion.div variants={itemVariants}>
          <Card className="glass-effect">
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Risk Level</CardTitle>
              <AlertCircle className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-green-500">
                Low
              </div>
              <p className="text-xs text-muted-foreground">
                Current risk assessment
              </p>
            </CardContent>
          </Card>
        </motion.div>
      </motion.div>

      {/* Compliance Frameworks Overview */}
      <motion.div variants={itemVariants}>
        <Card>
          <CardHeader>
            <CardTitle>Compliance Frameworks Status</CardTitle>
            <CardDescription>
              Current status and scores for all monitored compliance frameworks
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
              {frameworks.map((framework) => {
                const { status: _status, color } = getComplianceStatus(framework.overallScore)
                return (
                  <Card 
                    key={framework.id}
                    className={`cursor-pointer transition-all hover:shadow-md ${
                      selectedFramework === framework.id ? 'ring-2 ring-primary' : ''
                    }`}
                    onClick={() => setSelectedFramework(framework.id)}
                  >
                    <CardHeader className="pb-2">
                      <div className="flex items-center justify-between">
                        <CardTitle className="text-base">{framework.name}</CardTitle>
                        <Badge 
                          variant={framework.status === 'compliant' ? 'default' : 'destructive'}
                        >
                          {framework.status}
                        </Badge>
                      </div>
                    </CardHeader>
                    <CardContent>
                      <div className="text-2xl font-bold mb-2" style={{ color }}>
                        {framework.overallScore}%
                      </div>
                      <Progress value={framework.overallScore} className="mb-3" />
                      <div className="flex justify-between text-xs text-muted-foreground">
                        <span>{framework.controls.compliant} compliant</span>
                        <span>{framework.controls.nonCompliant} non-compliant</span>
                      </div>
                    </CardContent>
                  </Card>
                )
              })}
            </div>
          </CardContent>
        </Card>
      </motion.div>

      {/* Main Content Tabs */}
      <Tabs defaultValue="overview" className="space-y-4">
        <TabsList className="grid w-full grid-cols-5">
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="controls">Controls</TabsTrigger>
          <TabsTrigger value="audit-trail">Audit Trail</TabsTrigger>
          <TabsTrigger value="data-protection">Data Protection</TabsTrigger>
          <TabsTrigger value="reports">Reports</TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="space-y-4">
          <motion.div
            variants={containerVariants}
            initial="hidden"
            animate="visible"
            className="grid gap-4 md:grid-cols-2"
          >
            <motion.div variants={itemVariants}>
              <Card>
                <CardHeader>
                  <CardTitle>Compliance Trends</CardTitle>
                  <CardDescription>
                    30-day compliance score trends across frameworks
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <ComplianceFrameworkChart frameworks={frameworks} />
                </CardContent>
              </Card>
            </motion.div>

            <motion.div variants={itemVariants}>
              <Card>
                <CardHeader>
                  <CardTitle>Policy Adherence</CardTitle>
                  <CardDescription>
                    Security policy compliance and violations
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <PolicyAdherenceChart />
                </CardContent>
              </Card>
            </motion.div>

            <motion.div variants={itemVariants} className="md:col-span-2">
              <Card>
                <CardHeader>
                  <CardTitle>
                    {selectedFrameworkData?.name} - Detailed Status
                  </CardTitle>
                  <CardDescription>
                    Control categories and compliance status
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  {selectedFrameworkData && (
                    <div className="space-y-4">
                      <div className="grid grid-cols-4 gap-4">
                        <div className="text-center">
                          <div className="text-2xl font-bold text-green-500">
                            {selectedFrameworkData.controls.compliant}
                          </div>
                          <div className="text-sm text-muted-foreground">Compliant</div>
                        </div>
                        <div className="text-center">
                          <div className="text-2xl font-bold text-yellow-500">
                            {selectedFrameworkData.controls.partial}
                          </div>
                          <div className="text-sm text-muted-foreground">Partial</div>
                        </div>
                        <div className="text-center">
                          <div className="text-2xl font-bold text-red-500">
                            {selectedFrameworkData.controls.nonCompliant}
                          </div>
                          <div className="text-sm text-muted-foreground">Non-Compliant</div>
                        </div>
                        <div className="text-center">
                          <div className="text-2xl font-bold">
                            {selectedFrameworkData.controls.total}
                          </div>
                          <div className="text-sm text-muted-foreground">Total Controls</div>
                        </div>
                      </div>
                      
                      <div className="space-y-2">
                        <div className="flex justify-between text-sm">
                          <span>Compliance Progress</span>
                          <span>{selectedFrameworkData.overallScore}%</span>
                        </div>
                        <Progress value={selectedFrameworkData.overallScore} />
                      </div>

                      <div className="grid grid-cols-2 gap-4 text-sm">
                        <div>
                          <span className="text-muted-foreground">Last Assessment:</span>
                          <div>{new Date(selectedFrameworkData.lastAssessment).toLocaleDateString()}</div>
                        </div>
                        <div>
                          <span className="text-muted-foreground">Next Assessment:</span>
                          <div>{new Date(selectedFrameworkData.nextAssessment).toLocaleDateString()}</div>
                        </div>
                      </div>
                    </div>
                  )}
                </CardContent>
              </Card>
            </motion.div>
          </motion.div>
        </TabsContent>

        <TabsContent value="controls" className="space-y-4">
          <motion.div variants={itemVariants}>
            <ComplianceControlsMatrix frameworkId={selectedFramework} />
          </motion.div>
        </TabsContent>

        <TabsContent value="audit-trail" className="space-y-4">
          <motion.div variants={itemVariants}>
            <AuditTrailTable />
          </motion.div>
        </TabsContent>

        <TabsContent value="data-protection" className="space-y-4">
          <motion.div variants={itemVariants}>
            <DataProtectionMetrics />
          </motion.div>
        </TabsContent>

        <TabsContent value="reports" className="space-y-4">
          <motion.div variants={itemVariants}>
            <Card>
              <CardHeader>
                <CardTitle>Compliance Reports</CardTitle>
                <CardDescription>
                  Generate and download compliance reports for auditors and regulators
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
                  {frameworks.map((framework) => (
                    <Card key={framework.id} className="glass-effect">
                      <CardHeader className="pb-2">
                        <CardTitle className="text-base">{framework.name}</CardTitle>
                      </CardHeader>
                      <CardContent>
                        <div className="space-y-3">
                          <div className="flex justify-between text-sm">
                            <span>Status:</span>
                            <Badge 
                              variant={framework.status === 'compliant' ? 'default' : 'destructive'}
                            >
                              {framework.status}
                            </Badge>
                          </div>
                          <div className="flex justify-between text-sm">
                            <span>Score:</span>
                            <span>{framework.overallScore}%</span>
                          </div>
                          <Button size="sm" className="w-full">
                            <Download className="h-4 w-4 mr-2" />
                            Download Report
                          </Button>
                        </div>
                      </CardContent>
                    </Card>
                  ))}
                </div>
              </CardContent>
            </Card>
          </motion.div>
        </TabsContent>
      </Tabs>
    </div>
  )
}