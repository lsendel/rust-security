import { describe, it, expect } from 'vitest'
import { cn, formatRelativeTime, debounce, throttle, sanitizeLogMessage, isValidEmail } from '../utils'

describe('Utils', () => {
  describe('cn (className utility)', () => {
    it('merges class names correctly', () => {
      expect(cn('base-class', 'additional-class')).toBe('base-class additional-class')
    })

    it('handles conditional classes', () => {
      expect(cn('base', true && 'conditional', false && 'hidden')).toBe('base conditional')
    })

    it('handles undefined and null values', () => {
      expect(cn('base', null, undefined, 'valid')).toBe('base valid')
    })
  })

  describe('formatRelativeTime', () => {
    it('formats recent times correctly', () => {
      const now = Date.now()
      const fiveMinutesAgo = new Date(now - 5 * 60 * 1000).toISOString()
      
      const result = formatRelativeTime(fiveMinutesAgo)
      expect(result).toContain('minute')
      expect(result).toContain('ago')
    })

    it('formats hours correctly', () => {
      const now = Date.now()
      const twoHoursAgo = new Date(now - 2 * 60 * 60 * 1000).toISOString()
      
      const result = formatRelativeTime(twoHoursAgo)
      expect(result).toContain('hour')
      expect(result).toContain('ago')
    })

    it('formats days correctly', () => {
      const now = Date.now()
      const threeDaysAgo = new Date(now - 3 * 24 * 60 * 60 * 1000).toISOString()
      
      expect(formatRelativeTime(threeDaysAgo)).toBe('3 days ago')
    })

    it('handles future dates', () => {
      const now = Date.now()
      const future = new Date(now + 60 * 1000).toISOString()
      
      const result = formatRelativeTime(future)
      expect(result).toContain('in')
    })
  })

  describe('debounce', () => {
    it('delays function execution', (done) => {
      let count = 0
      const increment = () => { count++ }
      const debouncedIncrement = debounce(increment, 50)
      
      debouncedIncrement()
      debouncedIncrement()
      debouncedIncrement()
      
      expect(count).toBe(0)
      
      setTimeout(() => {
        expect(count).toBe(1)
        done()
      }, 60)
    })

    it('passes arguments correctly', (done) => {
      let result = ''
      const append = (text: string) => { result += text }
      const debouncedAppend = debounce(append, 50)
      
      debouncedAppend('hello')
      
      setTimeout(() => {
        expect(result).toBe('hello')
        done()
      }, 60)
    })
  })

  describe('throttle', () => {
    it('limits function calls', (done) => {
      let count = 0
      const increment = () => { count++ }
      const throttledIncrement = throttle(increment, 100)
      
      throttledIncrement()
      throttledIncrement()
      throttledIncrement()
      
      expect(count).toBe(1)
      
      setTimeout(() => {
        throttledIncrement()
        expect(count).toBe(2)
        done()
      }, 150)
    })
  })

  describe('sanitizeLogMessage', () => {
    it('removes HTML/JS special characters', () => {
      const input = '<script>alert("xss")</script>'
      const result = sanitizeLogMessage(input)
      
      expect(result).not.toContain('<')
      expect(result).not.toContain('>')
      expect(result).not.toContain('"')
      expect(result).not.toContain("'")
    })

    it('removes control characters', () => {
      const input = 'test' + String.fromCharCode(0) + String.fromCharCode(0x1f) + String.fromCharCode(0x7f) + 'message'
      const result = sanitizeLogMessage(input)
      
      expect(result).toBe('testmessage')
    })

    it('removes javascript: protocol', () => {
      const input = 'javascript:alert("xss")'
      const result = sanitizeLogMessage(input)
      
      expect(result).not.toContain('javascript:')
    })

    it('limits message length', () => {
      const input = 'a'.repeat(300)
      const result = sanitizeLogMessage(input)
      
      expect(result.length).toBe(200)
    })

    it('handles empty strings', () => {
      expect(sanitizeLogMessage('')).toBe('')
    })

    it('preserves safe characters', () => {
      const input = 'Safe message with numbers 123 and symbols - _ .'
      const result = sanitizeLogMessage(input)
      
      expect(result).toBe(input)
    })
  })

  describe('isValidEmail', () => {
    it('validates correct email addresses', () => {
      expect(isValidEmail('user@example.com')).toBe(true)
      expect(isValidEmail('test.email+tag@domain.co.uk')).toBe(true)
      expect(isValidEmail('user123@test-domain.org')).toBe(true)
    })

    it('rejects invalid email addresses', () => {
      expect(isValidEmail('invalid-email')).toBe(false)
      expect(isValidEmail('@domain.com')).toBe(false)
      expect(isValidEmail('user@')).toBe(false)
      expect(isValidEmail('user@domain')).toBe(false)
      expect(isValidEmail('')).toBe(false)
      expect(isValidEmail('user space@domain.com')).toBe(false)
    })

    it('handles edge cases', () => {
      expect(isValidEmail('a@b.c')).toBe(true)
      expect(isValidEmail('user@domain.com.extra')).toBe(true)
    })
  })
})