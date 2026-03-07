import { Navigate } from 'react-router-dom'

export default function ProtectedRoute({ children, tier }) {
  const token = localStorage.getItem('sep_token')
  if (!token) return <Navigate to="/login" replace />
  return children
}