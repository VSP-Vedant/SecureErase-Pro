import { Routes, Route, Navigate } from 'react-router-dom'
import PublicVerify from './pages/PublicVerify'
import CertDetail from './pages/CertDetail'
import Login from './pages/Login'
import EnterpriseDashboard from './pages/EnterpriseDashboard'
import AdminDashboard from './pages/AdminDashboard'
import Layout from './components/Layout'
import ProtectedRoute from './components/ProtectedRoute'

export default function App() {
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route path="/" element={<PublicVerify />} />
        <Route path="/cert/:id" element={<CertDetail />} />
        <Route path="/login" element={<Login />} />
        <Route
          path="/enterprise"
          element={<ProtectedRoute tier="enterprise"><EnterpriseDashboard /></ProtectedRoute>}
        />
        <Route
          path="/admin"
          element={<ProtectedRoute tier="admin"><AdminDashboard /></ProtectedRoute>}
        />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Route>
    </Routes>
  )
}
