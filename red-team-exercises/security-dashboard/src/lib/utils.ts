import { type ClassValue, clsx } from "clsx"
import { twMerge } from "tailwind-merge"
import { format, formatDistance } from 'date-fns'

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

export function formatTimestamp(timestamp: number | Date): string {
  return format(new Date(timestamp), 'MMM dd, yyyy HH:mm:ss')
}

export function formatRelativeTime(timestamp: number | Date): string {
  return formatDistance(new Date(timestamp), new Date(), { addSuffix: true })
}

export function formatBytes(bytes: number): string {
  const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB']
  if (bytes === 0) return '0 Bytes'
  const i = Math.floor(Math.log(bytes) / Math.log(1024))
  return Math.round(bytes / Math.pow(1024, i) * 100) / 100 + ' ' + sizes[i]
}

export function formatNumber(num: number): string {
  return new Intl.NumberFormat().format(num)
}

export function formatPercentage(value: number): string {
  return `${(value * 100).toFixed(1)}%`
}

export function getSecurityColor(severity: string): string {
  switch (severity.toLowerCase()) {
    case 'critical':
      return 'text-security-critical'
    case 'high':
      return 'text-security-high'
    case 'medium':
      return 'text-security-medium'
    case 'low':
      return 'text-security-low'
    case 'info':
      return 'text-security-info'
    default:
      return 'text-muted-foreground'
  }
}

export function getSecurityBgColor(severity: string): string {
  switch (severity.toLowerCase()) {
    case 'critical':
      return 'bg-security-critical/10 border-security-critical/20'
    case 'high':
      return 'bg-security-high/10 border-security-high/20'
    case 'medium':
      return 'bg-security-medium/10 border-security-medium/20'
    case 'low':
      return 'bg-security-low/10 border-security-low/20'
    case 'info':
      return 'bg-security-info/10 border-security-info/20'
    default:
      return 'bg-muted/10 border-muted/20'
  }
}

export function debounce<T extends (...args: any[]) => any>(
  func: T,
  delay: number
): (...args: Parameters<T>) => void {
  let timeoutId: NodeJS.Timeout
  return (...args: Parameters<T>) => {
    clearTimeout(timeoutId)
    timeoutId = setTimeout(() => func(...args), delay)
  }
}

export function throttle<T extends (...args: any[]) => any>(
  func: T,
  limit: number
): (...args: Parameters<T>) => void {
  let inThrottle: boolean
  return (...args: Parameters<T>) => {
    if (!inThrottle) {
      func(...args)
      inThrottle = true
      setTimeout(() => inThrottle = false, limit)
    }
  }
}

export function generateId(): string {
  return Math.random().toString(36).substr(2, 9)
}

export function sanitizeInput(input: string): string {
  return input.replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
}

export function isValidEmail(email: string): boolean {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
  return emailRegex.test(email)
}

export function isValidIP(ip: string): boolean {
  const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/
  return ipRegex.test(ip)
}

export function calculateRiskScore(
  severity: string,
  frequency: number,
  impact: number
): number {
  const severityWeights = {
    critical: 5,
    high: 4,
    medium: 3,
    low: 2,
    info: 1
  }
  
  const weight = severityWeights[severity.toLowerCase() as keyof typeof severityWeights] || 1
  return Math.min(100, (weight * frequency * impact) / 10)
}

export function getComplianceStatus(score: number): {
  status: 'compliant' | 'partial' | 'non-compliant'
  color: string
} {
  if (score >= 90) {
    return { status: 'compliant', color: 'text-green-500' }
  } else if (score >= 70) {
    return { status: 'partial', color: 'text-yellow-500' }
  } else {
    return { status: 'non-compliant', color: 'text-red-500' }
  }
}