import { useState } from 'react'
import { Link, useLocation } from 'react-router-dom'
import { 
  Shield, 
  BarChart3, 
  Target, 
  FileText, 
  Settings, 
  AlertTriangle,
  Users,
  Cloud,
  TrendingUp,
  Menu,
  X,
  Bell,
  User,
  LogOut,
  Moon,
  Sun
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { useTheme } from '@/components/theme/theme-provider'
import { useSecurityAlerts } from '@/hooks/use-websocket'

interface LayoutProps {
  children: React.ReactNode
}

export function Layout({ children }: LayoutProps) {
  const [sidebarOpen, setSidebarOpen] = useState(true)
  const location = useLocation()
  const { theme, setTheme } = useTheme()
  const securityAlerts = useSecurityAlerts()

  const criticalAlerts = securityAlerts.filter(alert => alert.severity === 'critical').length

  const navigation = [
    {
      name: 'Dashboard',
      href: '/dashboard',
      icon: BarChart3,
      current: location.pathname === '/dashboard',
    },
    {
      name: 'Authentication Flow',
      href: '/auth-flow',
      icon: Shield,
      current: location.pathname === '/auth-flow',
    },
    {
      name: 'Threat Intelligence',
      href: '/threat-intelligence',
      icon: Target,
      current: location.pathname === '/threat-intelligence',
      badge: criticalAlerts > 0 ? criticalAlerts.toString() : undefined,
    },
    {
      name: 'Compliance & Audit',
      href: '/compliance',
      icon: FileText,
      current: location.pathname === '/compliance',
    },
    {
      name: 'Security Operations',
      href: '/security-ops',
      icon: AlertTriangle,
      current: location.pathname === '/security-ops',
    },
    {
      name: 'Incident Response',
      href: '/incident-response',
      icon: Users,
      current: location.pathname === '/incident-response',
    },
    {
      name: 'Analytics & Insights',
      href: '/analytics',
      icon: TrendingUp,
      current: location.pathname === '/analytics',
    },
    {
      name: 'Cloud Security',
      href: '/cloud-security',
      icon: Cloud,
      current: location.pathname === '/cloud-security',
    },
    {
      name: 'Executive Reports',
      href: '/reports',
      icon: FileText,
      current: location.pathname === '/reports',
    },
    {
      name: 'Settings',
      href: '/settings',
      icon: Settings,
      current: location.pathname === '/settings',
    },
  ]

  return (
    <div className="flex h-screen bg-background">
      {/* Sidebar */}
      <div
        className={cn(
          "flex flex-col bg-card border-r transition-all duration-300",
          sidebarOpen ? "w-64" : "w-16"
        )}
      >
        {/* Logo */}
        <div className="flex items-center justify-between p-4 border-b">
          {sidebarOpen && (
            <div className="flex items-center space-x-2">
              <Shield className="h-8 w-8 text-primary" />
              <span className="text-xl font-bold">SecureAuth</span>
            </div>
          )}
          <Button
            variant="ghost"
            size="icon"
            onClick={() => setSidebarOpen(!sidebarOpen)}
          >
            {sidebarOpen ? <X className="h-4 w-4" /> : <Menu className="h-4 w-4" />}
          </Button>
        </div>

        {/* Navigation */}
        <nav className="flex-1 overflow-y-auto p-4">
          <ul className="space-y-2">
            {navigation.map((item) => (
              <li key={item.name}>
                <Link
                  to={item.href}
                  className={cn(
                    "flex items-center rounded-lg px-3 py-2 text-sm font-medium transition-colors",
                    item.current
                      ? "bg-primary text-primary-foreground"
                      : "text-muted-foreground hover:bg-accent hover:text-accent-foreground"
                  )}
                >
                  <item.icon className="h-4 w-4" />
                  {sidebarOpen && (
                    <>
                      <span className="ml-3">{item.name}</span>
                      {item.badge && (
                        <Badge 
                          variant="destructive" 
                          className="ml-auto animate-pulse"
                        >
                          {item.badge}
                        </Badge>
                      )}
                    </>
                  )}
                </Link>
              </li>
            ))}
          </ul>
        </nav>

        {/* User Profile */}
        <div className="border-t p-4">
          <div className="flex items-center space-x-3">
            <div className="flex h-8 w-8 items-center justify-center rounded-full bg-primary">
              <User className="h-4 w-4 text-primary-foreground" />
            </div>
            {sidebarOpen && (
              <div className="flex-1">
                <p className="text-sm font-medium">Security Admin</p>
                <p className="text-xs text-muted-foreground">admin@company.com</p>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Main content */}
      <div className="flex flex-1 flex-col overflow-hidden">
        {/* Top bar */}
        <header className="flex items-center justify-between border-b bg-card px-6 py-3">
          <div className="flex items-center space-x-4">
            <h2 className="text-lg font-semibold">
              {navigation.find(item => item.current)?.name || 'Dashboard'}
            </h2>
          </div>
          
          <div className="flex items-center space-x-4">
            {/* Theme toggle */}
            <Button
              variant="ghost"
              size="icon"
              onClick={() => setTheme(theme === 'light' ? 'dark' : 'light')}
            >
              {theme === 'light' ? (
                <Moon className="h-4 w-4" />
              ) : (
                <Sun className="h-4 w-4" />
              )}
            </Button>

            {/* Notifications */}
            <Button variant="ghost" size="icon" className="relative">
              <Bell className="h-4 w-4" />
              {criticalAlerts > 0 && (
                <Badge 
                  variant="destructive" 
                  className="absolute -top-1 -right-1 h-5 w-5 rounded-full p-0 text-xs animate-pulse"
                >
                  {criticalAlerts}
                </Badge>
              )}
            </Button>

            {/* User menu */}
            <Button variant="ghost" size="icon">
              <LogOut className="h-4 w-4" />
            </Button>
          </div>
        </header>

        {/* Page content */}
        <main className="flex-1 overflow-auto">
          {children}
        </main>
      </div>
    </div>
  )
}