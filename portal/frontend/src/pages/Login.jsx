import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { login, verifyTOTP } from '../utils/api'

export default function Login() {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [totpCode, setTotpCode] = useState('')
  const [step, setStep] = useState('credentials') // 'credentials' | 'totp'
  const [partialToken, setPartialToken] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const navigate = useNavigate()

  const handleLogin = async (e) => {
    e.preventDefault()
    setLoading(true); setError('')
    try {
      const { data } = await login(email, password)
      if (data.mfa_required) {
        setPartialToken(data.access_token)
        localStorage.setItem('sep_token', data.access_token)
        setStep('totp')
      } else {
        localStorage.setItem('sep_token', data.access_token)
        navigate(data.role === 'admin' ? '/admin' : '/enterprise')
      }
    } catch(e) {
      setError(e.response?.data?.detail || 'Login failed')
    } finally { setLoading(false) }
  }

  const handleTOTP = async (e) => {
    e.preventDefault()
    setLoading(true); setError('')
    try {
      const { data } = await verifyTOTP(totpCode)
      localStorage.setItem('sep_token', data.access_token)
      navigate('/admin')
    } catch(e) {
      setError(e.response?.data?.detail || 'Invalid code')
    } finally { setLoading(false) }
  }

  return (
    <div className="max-w-sm mx-auto mt-16">
      <div className="bg-white rounded-xl border border-slate-200 p-8">
        <h1 className="text-xl font-bold text-slate-900 mb-6 text-center">
          {step === 'credentials' ? 'Sign In' : 'Two-Factor Authentication'}
        </h1>

        {step === 'credentials' ? (
          <form onSubmit={handleLogin} className="space-y-4">
            <input type="email" value={email} onChange={e => setEmail(e.target.value)}
              placeholder="Email" required
              className="w-full border border-slate-300 rounded-lg px-4 py-2.5 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500" />
            <input type="password" value={password} onChange={e => setPassword(e.target.value)}
              placeholder="Password" required
              className="w-full border border-slate-300 rounded-lg px-4 py-2.5 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500" />
            {error && <p className="text-red-500 text-sm">{error}</p>}
            <button type="submit" disabled={loading}
              className="w-full bg-blue-600 text-white py-2.5 rounded-lg text-sm font-medium hover:bg-blue-700 disabled:opacity-50">
              {loading ? 'Signing in...' : 'Sign In'}
            </button>
          </form>
        ) : (
          <form onSubmit={handleTOTP} className="space-y-4">
            <p className="text-sm text-slate-500 text-center">Enter the 6-digit code from your authenticator app.</p>
            <input type="text" inputMode="numeric" value={totpCode}
              onChange={e => setTotpCode(e.target.value)} placeholder="000000"
              maxLength={6} pattern="\d{6}" required
              className="w-full border border-slate-300 rounded-lg px-4 py-2.5 text-sm font-mono text-center tracking-widest focus:outline-none focus:ring-2 focus:ring-blue-500" />
            {error && <p className="text-red-500 text-sm">{error}</p>}
            <button type="submit" disabled={loading}
              className="w-full bg-blue-600 text-white py-2.5 rounded-lg text-sm font-medium hover:bg-blue-700 disabled:opacity-50">
              {loading ? 'Verifying...' : 'Verify'}
            </button>
          </form>
        )}
      </div>
    </div>
  )
}