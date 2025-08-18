export interface SecurityMetrics {
  timestamp: number
  authenticationSuccess: number
  authenticationFailure: number
  mfaUsage: number
  rateLimitTriggers: number
  idorAttempts: number
  tokenReplayAttempts: number
  totpReplayAttempts: number
  pkceDowngradeAttempts: number
  activeConnections: number
  responseTime: number
  errorRate: number
  circuitBreakerStatus: 'closed' | 'open' | 'half-open'
}

export interface ThreatEvent {
  id: string
  timestamp: number
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  type: string
  source: string
  sourceIp: string
  description: string
  details: Record<string, any>
  status: 'open' | 'investigating' | 'resolved' | 'false-positive'
  assignedTo?: string
  riskScore: number
  geolocation?: {
    country: string
    city: string
    lat: number
    lng: number
  }
}

export interface ComplianceControl {
  id: string
  name: string
  framework: 'SOC2' | 'PCI-DSS' | 'GDPR' | 'CCPA' | 'ISO27001'
  status: 'compliant' | 'partial' | 'non-compliant' | 'not-applicable'
  score: number
  lastAssessed: number
  evidence: string[]
  remediation?: string
  owner: string
}

export interface IncidentResponse {
  id: string
  title: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  status: 'open' | 'investigating' | 'resolved' | 'closed'
  createdAt: number
  updatedAt: number
  assignedTo: string
  description: string
  timeline: IncidentTimelineEvent[]
  affectedSystems: string[]
  impactAssessment: string
  rootCause?: string
  remediation?: string
  lessonsLearned?: string
}

export interface IncidentTimelineEvent {
  id: string
  timestamp: number
  type: 'detection' | 'escalation' | 'response' | 'communication' | 'resolution'
  description: string
  user: string
}

export interface UserRiskProfile {
  userId: string
  username: string
  riskScore: number
  riskFactors: string[]
  lastActivity: number
  failedLogins: number
  suspiciousActivities: number
  mfaCompliance: boolean
  sessionAnomalies: number
}

export interface CloudSecurityPosture {
  provider: 'aws' | 'gcp' | 'azure'
  region: string
  account: string
  resources: {
    total: number
    compliant: number
    nonCompliant: number
    critical: number
  }
  findings: CloudSecurityFinding[]
  lastScan: number
}

export interface CloudSecurityFinding {
  id: string
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  category: string
  title: string
  description: string
  resource: string
  recommendation: string
  status: 'open' | 'suppressed' | 'resolved'
}

export interface AttackPattern {
  id: string
  name: string
  tactics: string[]
  techniques: string[]
  frequency: number
  successRate: number
  mitigations: string[]
  indicators: string[]
  attribution?: string
}

export interface MLInsight {
  id: string
  type: 'anomaly' | 'prediction' | 'classification' | 'clustering'
  title: string
  description: string
  confidence: number
  timestamp: number
  data: Record<string, any>
  actionable: boolean
  recommendations: string[]
}

export interface ExecutiveMetric {
  name: string
  value: number
  unit?: string
  trend: 'up' | 'down' | 'stable'
  trendPercentage: number
  target?: number
  category: 'security' | 'performance' | 'compliance' | 'business'
}

export interface SOARAutomation {
  id: string
  name: string
  trigger: string
  status: 'active' | 'paused' | 'error'
  executionCount: number
  successRate: number
  averageExecutionTime: number
  lastExecution: number
  description: string
}

export interface SecurityAlert {
  id: string
  title: string
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  timestamp: number
  source: string
  description: string
  acknowledged: boolean
  assignedTo?: string
  correlatedEvents: string[]
}

export interface PerformanceMetric {
  timestamp: number
  cpuUsage: number
  memoryUsage: number
  diskUsage: number
  networkIn: number
  networkOut: number
  responseTime: number
  throughput: number
  errorRate: number
  activeConnections: number
}

export interface AuditLog {
  id: string
  timestamp: number
  userId: string
  username: string
  action: string
  resource: string
  outcome: 'success' | 'failure'
  details: Record<string, any>
  sourceIp: string
  userAgent: string
  sessionId: string
}