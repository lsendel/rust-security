import { Routes, Route, Navigate } from 'react-router-dom'
import { AuthProvider } from './contexts/AuthContext'
import LoginPage from './pages/LoginPage'
import CallbackPage from './pages/CallbackPage'
import ProtectedRoute from './components/Auth/ProtectedRoute'
import Layout from './components/Layout/Layout'
import ProfilePage from './pages/ProfilePage'
import SecurityPage from './pages/SecurityPage'
import SessionsPage from './pages/SessionsPage'
import ConsentsPage from './pages/ConsentsPage'

const App = () => {
  return (
    <AuthProvider>
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route path="/callback" element={<CallbackPage />} />
        <Route
          path="/*"
          element={
            <ProtectedRoute>
              <Layout>
                <Routes>
                  <Route path="/profile" element={<ProfilePage />} />
                  <Route path="/security" element={<SecurityPage />} />
                  <Route path="/sessions" element={<SessionsPage />} />
                  <Route path="/consents" element={<ConsentsPage />} />
                  <Route path="/" element={<Navigate to="/profile" replace />} />
                </Routes>
              </Layout>
            </ProtectedRoute>
          }
        />
      </Routes>
    </AuthProvider>
  )
}

export default App
