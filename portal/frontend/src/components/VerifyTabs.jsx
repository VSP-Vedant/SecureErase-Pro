import { useState } from 'react'
import { verifyById, verifyByUpload, verifyByQRPayload } from '../utils/api'

export default function VerifyTabs({ onResult }) {
  const [tab, setTab] = useState('id')
  const [certId, setCertId] = useState('')
  const [file, setFile] = useState(null)
  const [qrPayload, setQrPayload] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const handle = async (fn) => {
    setLoading(true); setError('')
    try {
      const { data } = await fn()
      onResult(data)
    } catch(e) {
      setError(e.response?.data?.detail || 'Verification failed')
    } finally {
      setLoading(false)
    }
  }

  const TABS = [
    { id: 'id', label: '🔍 Certificate ID' },
    { id: 'upload', label: '📄 Upload JSON' },
    { id: 'qr', label: '📷 QR Code' },
  ]

  return (
    <div className="bg-white rounded-xl border border-slate-200 overflow-hidden">
      <div className="flex border-b border-slate-200">
        {TABS.map(t => (
          <button
            key={t.id}
            onClick={() => { setTab(t.id); setError('') }}
            className={`flex-1 py-3 text-sm font-medium transition-colors ${
              tab === t.id
                ? 'bg-blue-50 text-blue-700 border-b-2 border-blue-600'
                : 'text-slate-500 hover:text-slate-700'
            }`}
          >
            {t.label}
          </button>
        ))}
      </div>

      <div className="p-6">
        {tab === 'id' && (
          <div className="flex gap-3">
            <input
              type="text"
              value={certId}
              onChange={e => setCertId(e.target.value)}
              placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
              className="flex-1 border border-slate-300 rounded-lg px-4 py-2.5 text-sm font-mono focus:outline-none focus:ring-2 focus:ring-blue-500"
              onKeyDown={e => e.key === 'Enter' && certId && handle(() => verifyById(certId))}
            />
            <button
              onClick={() => certId && handle(() => verifyById(certId))}
              disabled={!certId || loading}
              className="bg-blue-600 text-white px-5 py-2.5 rounded-lg text-sm font-medium hover:bg-blue-700 disabled:opacity-50"
            >
              {loading ? 'Verifying...' : 'Verify'}
            </button>
          </div>
        )}

        {tab === 'upload' && (
          <div className="space-y-4">
            <label className="flex flex-col items-center justify-center w-full h-32 border-2 border-dashed border-slate-300 rounded-lg cursor-pointer hover:border-blue-400 hover:bg-blue-50 transition-colors">
              <span className="text-slate-500 text-sm">{file ? file.name : 'Click or drag certificate JSON here'}</span>
              <input type="file" accept=".json,application/json" className="hidden"
                onChange={e => setFile(e.target.files[0])} />
            </label>
            <button
              onClick={() => file && handle(() => verifyByUpload(file))}
              disabled={!file || loading}
              className="w-full bg-blue-600 text-white py-2.5 rounded-lg text-sm font-medium hover:bg-blue-700 disabled:opacity-50"
            >
              {loading ? 'Verifying...' : 'Verify Certificate'}
            </button>
          </div>
        )}

        {tab === 'qr' && (
          <div className="space-y-4">
            <p className="text-sm text-slate-500">Paste the QR code URL or certificate ID from your QR code scanner:</p>
            <div className="flex gap-3">
              <input
                type="text"
                value={qrPayload}
                onChange={e => setQrPayload(e.target.value)}
                placeholder="https://verify.example.com/cert/..."
                className="flex-1 border border-slate-300 rounded-lg px-4 py-2.5 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
              />
              <button
                onClick={() => qrPayload && handle(() => verifyByQRPayload(qrPayload))}
                disabled={!qrPayload || loading}
                className="bg-blue-600 text-white px-5 py-2.5 rounded-lg text-sm font-medium hover:bg-blue-700 disabled:opacity-50"
              >
                {loading ? '...' : 'Verify'}
              </button>
            </div>
          </div>
        )}

        {error && (
          <div className="mt-4 p-3 bg-red-50 border border-red-200 rounded-lg text-red-700 text-sm">
            {error}
          </div>
        )}
      </div>
    </div>
  )
}