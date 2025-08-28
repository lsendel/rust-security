import React, { createContext, useState, useCallback, useEffect, ReactNode } from 'react'

interface User {
  id: string
  email: string
  role: string
  permissions: string[]
}

interface AuthContextType {
  currentUser: User | null
  isAuthenticated: boolean
  getAuthToken: () => Promise<string | null>
  login: (email: string, password: string) => Promise<void>
  logout: () => Promise<void>
  refreshToken: () => Promise<void>
}

const AuthContext = createContext<AuthContextType | undefined>(undefined)

// Secure token storage using sessionStorage instead of localStorage
// For production, consider using httpOnly cookies
class SecureTokenStorage {
  private static TOKEN_KEY = 'auth_token_secure'
  private static REFRESH_KEY = 'refresh_token_secure'
  
  static setTokens(authToken: string, refreshToken: string) {
    // Store in sessionStorage (cleared when browser closes)
    sessionStorage.setItem(this.TOKEN_KEY, authToken)
    sessionStorage.setItem(this.REFRESH_KEY, refreshToken)
  }
  
  static getAuthToken(): string | null {
    return sessionStorage.getItem(this.TOKEN_KEY)
  }
  
  static getRefreshToken(): string | null {
    return sessionStorage.getItem(this.REFRESH_KEY)
  }
  
  static clearTokens() {
    sessionStorage.removeItem(this.TOKEN_KEY)
    sessionStorage.removeItem(this.REFRESH_KEY)
  }
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [currentUser, setCurrentUser] = useState<User | null>(null)
  const [isAuthenticated, setIsAuthenticated] = useState(false)

  const refreshTokenInternal = useCallback(async () => {
    try {
      const refreshToken = SecureTokenStorage.getRefreshToken()
      if (!refreshToken) {
        throw new Error('No refresh token available')
      }

      const response = await fetch('/api/auth/refresh', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ refreshToken }),
      })

      if (!response.ok) {
        throw new Error('Token refresh failed')
      }

      const data = await response.json()
      SecureTokenStorage.setTokens(data.authToken, data.refreshToken)
    } catch (error) {
      console.error('Token refresh error:', error)
      SecureTokenStorage.clearTokens()
      setCurrentUser(null)
      setIsAuthenticated(false)
    }
  }, [])

  const getAuthToken = useCallback(async (): Promise<string | null> => {
    try {
      const token = SecureTokenStorage.getAuthToken()
      if (!token) {
        return null
      }
      
      // Validate token hasn't expired
      const payload = JSON.parse(atob(token.split('.')[1]))
      if (payload.exp * 1000 < Date.now()) {
        await refreshTokenInternal()
        return SecureTokenStorage.getAuthToken()
      }
      
      return token
    } catch (error) {
      console.error('Error getting auth token:', error)
      return null
    }
  }, [refreshTokenInternal])

  const login = useCallback(async (email: string, password: string) => {
    try {
      const response = await fetch('/api/auth/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ email, password }),
      })

      if (!response.ok) {
        throw new Error('Login failed')
      }

      const data = await response.json()
      
      // Validate response structure
      if (!data.user || !data.authToken || !data.refreshToken) {
        throw new Error('Invalid login response')
      }

      SecureTokenStorage.setTokens(data.authToken, data.refreshToken)
      setCurrentUser(data.user)
      setIsAuthenticated(true)
    } catch (error) {
      console.error('Login error:', error)
      throw error
    }
  }, [])

  const logout = useCallback(async () => {
    try {
      const token = await getAuthToken()
      if (token) {
        await fetch('/api/auth/logout', {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${token}`,
          },
        })
      }
    } catch (error) {
      console.error('Logout error:', error)
    } finally {
      SecureTokenStorage.clearTokens()
      setCurrentUser(null)
      setIsAuthenticated(false)
    }
  }, [getAuthToken])

  const refreshToken = useCallback(async () => {
    await refreshTokenInternal()
  }, [refreshTokenInternal])

  // Check authentication status on mount
  useEffect(() => {
    const checkAuth = async () => {
      const token = await getAuthToken()
      if (token) {
        try {
          const response = await fetch('/api/auth/me', {
            headers: {
              'Authorization': `Bearer ${token}`,
            },
          })
          
          if (response.ok) {
            const user = await response.json()
            setCurrentUser(user)
            setIsAuthenticated(true)
          } else {
            await logout()
          }
        } catch (error) {
          console.error('Auth check error:', error)
          await logout()
        }
      }
    }
    
    checkAuth()
  }, [getAuthToken, logout])

  const value = {
    currentUser,
    isAuthenticated,
    getAuthToken,
    login,
    logout,
    refreshToken,
  }

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

export { AuthContext }
export type { User, AuthContextType }