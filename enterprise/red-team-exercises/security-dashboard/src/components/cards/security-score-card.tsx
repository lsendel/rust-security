import React, { useState, useEffect } from 'react'
import { motion } from 'framer-motion'
import { Shield, TrendingUp, TrendingDown, Minus } from 'lucide-react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Progress } from '@/components/ui/progress'
import { Badge } from '@/components/ui/badge'

interface SecurityScore {
  overall: number
  authentication: number
  authorization: number
  dataProtection: number
  networkSecurity: number
  incidentResponse: number
  compliance: number
  trend: 'up' | 'down' | 'stable'
  trendPercentage: number
}

export function SecurityScoreCard() {
  const [securityScore, setSecurityScore] = useState<SecurityScore>({
    overall: 0,
    authentication: 0,
    authorization: 0,
    dataProtection: 0,
    networkSecurity: 0,
    incidentResponse: 0,
    compliance: 0,
    trend: 'stable',
    trendPercentage: 0
  })

  // Simulate real-time score updates
  useEffect(() => {
    const mockScore: SecurityScore = {
      overall: 87,
      authentication: 92,
      authorization: 89,
      dataProtection: 85,
      networkSecurity: 83,
      incidentResponse: 78,
      compliance: 94,
      trend: 'up',
      trendPercentage: 3.2
    }

    // Animate score changes
    const timer = setInterval(() => {
      setSecurityScore(prev => ({
        ...prev,
        overall: Math.min(prev.overall + 1, mockScore.overall),
        authentication: Math.min(prev.authentication + 1, mockScore.authentication),
        authorization: Math.min(prev.authorization + 1, mockScore.authorization),
        dataProtection: Math.min(prev.dataProtection + 1, mockScore.dataProtection),
        networkSecurity: Math.min(prev.networkSecurity + 1, mockScore.networkSecurity),
        incidentResponse: Math.min(prev.incidentResponse + 1, mockScore.incidentResponse),
        compliance: Math.min(prev.compliance + 1, mockScore.compliance),
        trend: mockScore.trend,
        trendPercentage: mockScore.trendPercentage
      }))
    }, 100)

    return () => clearInterval(timer)
  }, [])

  const getScoreColor = (score: number) => {
    if (score >= 90) return 'text-green-500'
    if (score >= 80) return 'text-yellow-500'
    if (score >= 70) return 'text-orange-500'
    return 'text-red-500'
  }

  const getScoreLevel = (score: number) => {
    if (score >= 90) return 'Excellent'
    if (score >= 80) return 'Good'
    if (score >= 70) return 'Fair'
    return 'Needs Improvement'
  }

  const getTrendIcon = () => {
    switch (securityScore.trend) {
      case 'up':
        return <TrendingUp className="h-4 w-4 text-green-500" />
      case 'down':
        return <TrendingDown className="h-4 w-4 text-red-500" />
      default:
        return <Minus className="h-4 w-4 text-muted-foreground" />
    }
  }

  const categories = [
    { name: 'Authentication', score: securityScore.authentication, key: 'auth' },
    { name: 'Authorization', score: securityScore.authorization, key: 'authz' },
    { name: 'Data Protection', score: securityScore.dataProtection, key: 'data' },
    { name: 'Network Security', score: securityScore.networkSecurity, key: 'network' },
    { name: 'Incident Response', score: securityScore.incidentResponse, key: 'incident' },
    { name: 'Compliance', score: securityScore.compliance, key: 'compliance' }
  ]

  return (
    <Card className="glass-effect">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Shield className="h-5 w-5 text-primary" />
          Security Score
        </CardTitle>
        <CardDescription>
          Overall security posture assessment
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-6">
        {/* Overall Score */}
        <div className="text-center">
          <motion.div
            className={`text-4xl font-bold ${getScoreColor(securityScore.overall)}`}
            initial={{ scale: 0 }}
            animate={{ scale: 1 }}
            transition={{ type: "spring", stiffness: 100 }}
          >
            {securityScore.overall}
          </motion.div>
          <div className="text-sm text-muted-foreground mb-2">
            {getScoreLevel(securityScore.overall)}
          </div>
          <div className="flex items-center justify-center gap-1 text-sm">
            {getTrendIcon()}
            <span className={
              securityScore.trend === 'up' ? 'text-green-500' : 
              securityScore.trend === 'down' ? 'text-red-500' : 'text-muted-foreground'
            }>
              {securityScore.trendPercentage > 0 && securityScore.trend !== 'stable' && 
                `${securityScore.trendPercentage}%`
              }
              {securityScore.trend === 'stable' && 'No change'}
            </span>
          </div>
        </div>

        {/* Category Breakdown */}
        <div className="space-y-4">
          <h4 className="text-sm font-medium">Category Breakdown</h4>
          {categories.map((category, index) => (
            <motion.div
              key={category.key}
              initial={{ opacity: 0, x: -20 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: index * 0.1 }}
              className="space-y-2"
            >
              <div className="flex justify-between items-center text-sm">
                <span>{category.name}</span>
                <Badge 
                  variant="outline"
                  className={getScoreColor(category.score)}
                >
                  {category.score}%
                </Badge>
              </div>
              <Progress 
                value={category.score} 
                className="h-2"
              />
            </motion.div>
          ))}
        </div>

        {/* Recent Changes */}
        <div className="pt-4 border-t">
          <h4 className="text-sm font-medium mb-3">Recent Improvements</h4>
          <div className="space-y-2 text-sm">
            <div className="flex items-center justify-between">
              <span className="text-muted-foreground">MFA Implementation</span>
              <Badge variant="outline" className="text-green-500">
                +5%
              </Badge>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-muted-foreground">Rate Limiting</span>
              <Badge variant="outline" className="text-green-500">
                +3%
              </Badge>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-muted-foreground">Compliance Updates</span>
              <Badge variant="outline" className="text-green-500">
                +2%
              </Badge>
            </div>
          </div>
        </div>
      </CardContent>
    </Card>
  )
}