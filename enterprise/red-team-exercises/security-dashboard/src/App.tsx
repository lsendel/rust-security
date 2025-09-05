import { Routes, Route, Navigate } from 'react-router-dom'
import { ThemeProvider } from './components/theme/theme-provider'
import { WebSocketProvider } from './hooks/use-websocket'
import { Layout } from './components/layout/layout'
import { Dashboard } from './pages/dashboard'
import { ThreatIntelligence } from './pages/threat-intelligence'
import { ComplianceAudit } from './pages/compliance-audit'
import { SecurityOperations } from './pages/security-operations'
import { AnalyticsInsights } from './pages/analytics-insights'
import { CloudSecurity } from './pages/cloud-security'
import { ExecutiveReports } from './pages/executive-reports'
import { Settings } from './pages/settings'
import { AuthenticationFlow } from './pages/authentication-flow'
import { IncidentResponse } from './pages/incident-response'

function App() {
  return (
    <ThemeProvider defaultTheme="dark" storageKey="security-dashboard-theme">
      <WebSocketProvider url="ws://localhost:8080/ws">
        <Layout>
          <Routes>
            <Route path="/" element={<Navigate to="/dashboard" replace />} />
            <Route path="/dashboard" element={<Dashboard />} />
            <Route path="/auth-flow" element={<AuthenticationFlow />} />
            <Route path="/threat-intelligence" element={<ThreatIntelligence />} />
            <Route path="/compliance" element={<ComplianceAudit />} />
            <Route path="/security-ops" element={<SecurityOperations />} />
            <Route path="/incident-response" element={<IncidentResponse />} />
            <Route path="/analytics" element={<AnalyticsInsights />} />
            <Route path="/cloud-security" element={<CloudSecurity />} />
            <Route path="/reports" element={<ExecutiveReports />} />
            <Route path="/settings" element={<Settings />} />
          </Routes>
        </Layout>
      </WebSocketProvider>
    </ThemeProvider>
  )
}

export default App