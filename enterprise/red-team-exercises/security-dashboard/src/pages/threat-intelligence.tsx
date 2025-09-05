import { useState, useMemo } from 'react'
import { motion } from 'framer-motion'
import { 
  Target, 
  TrendingUp, 
  Globe, 
  AlertTriangle,
  Eye,
  Filter,
  Download,
  RefreshCw
} from 'lucide-react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { ThreatMapVisualization } from '@/components/charts/threat-map'
import { AttackPatternChart } from '@/components/charts/attack-pattern-chart'
import { ThreatTrendChart } from '@/components/charts/threat-trend-chart'
import { IOCTable } from '@/components/tables/ioc-table'
import { ThreatActorProfiles } from '@/components/threat/threat-actor-profiles'
import { RiskScoreMatrix } from '@/components/charts/risk-score-matrix'
import { useThreatEvents } from '@/hooks/use-websocket'
import { useQuery } from '@tanstack/react-query'
import { formatNumber, formatRelativeTime } from '@/lib/utils'

export function ThreatIntelligence() {
  const [selectedFilter, setSelectedFilter] = useState('all')
  const [searchQuery, setSearchQuery] = useState('')
  const [selectedTimeRange, setSelectedTimeRange] = useState('24h')
  
  const threatEvents = useThreatEvents()

  // Fetch threat intelligence data
  const { data: _threatIntelData, refetch, isLoading: _isLoading } = useQuery({
    queryKey: ['threat-intelligence', selectedTimeRange],
    queryFn: async () => {
      const response = await fetch(`/api/threat-intelligence?timeRange=${selectedTimeRange}`)
      return response.json()
    },
    refetchInterval: 60000, // Refresh every minute
  })

  // Filter and search threats
  const filteredThreats = useMemo(() => {
    let filtered = threatEvents

    if (selectedFilter !== 'all') {
      filtered = filtered.filter(threat => threat.severity === selectedFilter)
    }

    if (searchQuery) {
      filtered = filtered.filter(threat => 
        threat.type.toLowerCase().includes(searchQuery.toLowerCase()) ||
        threat.sourceIp.includes(searchQuery) ||
        threat.source.toLowerCase().includes(searchQuery.toLowerCase())
      )
    }

    return filtered
  }, [threatEvents, selectedFilter, searchQuery])

  // Calculate threat statistics
  const threatStats = useMemo(() => {
    const total = filteredThreats.length
    const critical = filteredThreats.filter(t => t.severity === 'critical').length
    const high = filteredThreats.filter(t => t.severity === 'high').length
    const uniqueIPs = new Set(filteredThreats.map(t => t.sourceIp)).size
    const uniqueCountries = new Set(
      filteredThreats
        .filter(t => t.geolocation?.country)
        .map(t => t.geolocation!.country)
    ).size

    return { total, critical, high, uniqueIPs, uniqueCountries }
  }, [filteredThreats])

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
          <h1 className="text-3xl font-bold tracking-tight">Threat Intelligence</h1>
          <p className="text-muted-foreground">
            Real-time threat feeds and attack pattern analysis
          </p>
        </div>
        <div className="flex items-center space-x-2">
          <Button variant="outline" onClick={() => refetch()}>
            <RefreshCw className="h-4 w-4 mr-2" />
            Refresh
          </Button>
          <Button variant="outline">
            <Download className="h-4 w-4 mr-2" />
            Export
          </Button>
          <Select value={selectedTimeRange} onValueChange={setSelectedTimeRange}>
            <SelectTrigger className="w-32">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="1h">Last Hour</SelectItem>
              <SelectItem value="6h">Last 6 Hours</SelectItem>
              <SelectItem value="24h">Last 24 Hours</SelectItem>
              <SelectItem value="7d">Last 7 Days</SelectItem>
              <SelectItem value="30d">Last 30 Days</SelectItem>
            </SelectContent>
          </Select>
        </div>
      </div>

      {/* Filters */}
      <div className="flex items-center space-x-4">
        <div className="flex items-center space-x-2">
          <Filter className="h-4 w-4" />
          <Select value={selectedFilter} onValueChange={setSelectedFilter}>
            <SelectTrigger className="w-40">
              <SelectValue placeholder="Filter by severity" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All Severities</SelectItem>
              <SelectItem value="critical">Critical</SelectItem>
              <SelectItem value="high">High</SelectItem>
              <SelectItem value="medium">Medium</SelectItem>
              <SelectItem value="low">Low</SelectItem>
            </SelectContent>
          </Select>
        </div>
        <Input
          placeholder="Search threats, IPs, or sources..."
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          className="max-w-sm"
        />
      </div>

      {/* Key Metrics */}
      <motion.div
        variants={containerVariants}
        initial="hidden"
        animate="visible"
        className="grid gap-4 md:grid-cols-2 lg:grid-cols-5"
      >
        <motion.div variants={itemVariants}>
          <Card className="glass-effect">
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Total Threats</CardTitle>
              <Target className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-blue-500">
                {formatNumber(threatStats.total)}
              </div>
              <p className="text-xs text-muted-foreground">
                Active threat events
              </p>
            </CardContent>
          </Card>
        </motion.div>

        <motion.div variants={itemVariants}>
          <Card className="glass-effect">
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Critical Threats</CardTitle>
              <AlertTriangle className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-red-500">
                {formatNumber(threatStats.critical)}
              </div>
              <p className="text-xs text-muted-foreground">
                Immediate attention required
              </p>
            </CardContent>
          </Card>
        </motion.div>

        <motion.div variants={itemVariants}>
          <Card className="glass-effect">
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">High Priority</CardTitle>
              <TrendingUp className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-orange-500">
                {formatNumber(threatStats.high)}
              </div>
              <p className="text-xs text-muted-foreground">
                High severity events
              </p>
            </CardContent>
          </Card>
        </motion.div>

        <motion.div variants={itemVariants}>
          <Card className="glass-effect">
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Unique IPs</CardTitle>
              <Globe className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-purple-500">
                {formatNumber(threatStats.uniqueIPs)}
              </div>
              <p className="text-xs text-muted-foreground">
                Distinct attack sources
              </p>
            </CardContent>
          </Card>
        </motion.div>

        <motion.div variants={itemVariants}>
          <Card className="glass-effect">
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Countries</CardTitle>
              <Eye className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-green-500">
                {formatNumber(threatStats.uniqueCountries)}
              </div>
              <p className="text-xs text-muted-foreground">
                Geographic diversity
              </p>
            </CardContent>
          </Card>
        </motion.div>
      </motion.div>

      {/* Main Content */}
      <Tabs defaultValue="overview" className="space-y-4">
        <TabsList className="grid w-full grid-cols-6">
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="threat-map">Threat Map</TabsTrigger>
          <TabsTrigger value="attack-patterns">Attack Patterns</TabsTrigger>
          <TabsTrigger value="ioc">IOCs</TabsTrigger>
          <TabsTrigger value="actors">Threat Actors</TabsTrigger>
          <TabsTrigger value="risk-analysis">Risk Analysis</TabsTrigger>
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
                  <CardTitle>Threat Trends</CardTitle>
                  <CardDescription>
                    24-hour threat activity and patterns
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <ThreatTrendChart threats={filteredThreats} />
                </CardContent>
              </Card>
            </motion.div>

            <motion.div variants={itemVariants}>
              <Card>
                <CardHeader>
                  <CardTitle>Risk Score Distribution</CardTitle>
                  <CardDescription>
                    Threat severity and risk assessment matrix
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <RiskScoreMatrix threats={filteredThreats} />
                </CardContent>
              </Card>
            </motion.div>

            <motion.div variants={itemVariants} className="md:col-span-2">
              <Card>
                <CardHeader>
                  <CardTitle>Recent Threat Events</CardTitle>
                  <CardDescription>
                    Latest security threats and incidents
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-3 max-h-96 overflow-y-auto scrollbar-thin">
                    {filteredThreats.slice(0, 10).map((threat) => (
                      <div
                        key={threat.id}
                        className="flex items-center justify-between p-3 border rounded-lg"
                      >
                        <div className="flex items-center space-x-3">
                          <Badge 
                            variant={threat.severity === 'critical' ? 'destructive' : 'outline'}
                          >
                            {threat.severity}
                          </Badge>
                          <div>
                            <div className="font-medium">{threat.type}</div>
                            <div className="text-sm text-muted-foreground">
                              {threat.sourceIp} • {threat.source}
                            </div>
                          </div>
                        </div>
                        <div className="text-right">
                          <div className="text-sm font-medium">
                            Risk: {threat.riskScore}/100
                          </div>
                          <div className="text-xs text-muted-foreground">
                            {formatRelativeTime(threat.timestamp)}
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>
            </motion.div>
          </motion.div>
        </TabsContent>

        <TabsContent value="threat-map" className="space-y-4">
          <motion.div variants={itemVariants}>
            <ThreatMapVisualization threats={filteredThreats} />
          </motion.div>
        </TabsContent>

        <TabsContent value="attack-patterns" className="space-y-4">
          <motion.div variants={itemVariants}>
            <AttackPatternChart threats={filteredThreats} />
          </motion.div>
        </TabsContent>

        <TabsContent value="ioc" className="space-y-4">
          <motion.div variants={itemVariants}>
            <IOCTable threats={filteredThreats} />
          </motion.div>
        </TabsContent>

        <TabsContent value="actors" className="space-y-4">
          <motion.div variants={itemVariants}>
            <ThreatActorProfiles threats={filteredThreats} />
          </motion.div>
        </TabsContent>

        <TabsContent value="risk-analysis" className="space-y-4">
          <motion.div variants={itemVariants}>
            <Card>
              <CardHeader>
                <CardTitle>Advanced Risk Analysis</CardTitle>
                <CardDescription>
                  Multi-dimensional threat assessment and prediction
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="grid gap-4 md:grid-cols-2">
                  <div className="space-y-4">
                    <h4 className="font-medium">Risk Factors</h4>
                    <div className="space-y-2">
                      <div className="flex justify-between">
                        <span>Attack Frequency</span>
                        <Badge variant="outline">High</Badge>
                      </div>
                      <div className="flex justify-between">
                        <span>Source Diversity</span>
                        <Badge variant="outline">Medium</Badge>
                      </div>
                      <div className="flex justify-between">
                        <span>Payload Sophistication</span>
                        <Badge variant="outline">High</Badge>
                      </div>
                      <div className="flex justify-between">
                        <span>Geographic Spread</span>
                        <Badge variant="outline">Global</Badge>
                      </div>
                    </div>
                  </div>
                  <div className="space-y-4">
                    <h4 className="font-medium">Predicted Trends</h4>
                    <div className="space-y-2">
                      <div className="flex justify-between">
                        <span>Next 24h Attack Volume</span>
                        <span className="text-orange-500">+15%</span>
                      </div>
                      <div className="flex justify-between">
                        <span>New Attack Vectors</span>
                        <span className="text-red-500">3 expected</span>
                      </div>
                      <div className="flex justify-between">
                        <span>Critical Escalation Risk</span>
                        <span className="text-red-500">High</span>
                      </div>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>
          </motion.div>
        </TabsContent>
      </Tabs>
    </div>
  )
}