import { useState, useEffect } from 'react'
import { adminStats, adminCertificates, adminFlagged, adminRevoke } from '../utils/api'
import StatusBadge from '../components/StatusBadge'
import { formatDate } from '../utils/statusHelpers'

function StatCard({ label, value, color }) {
  return (
    <div className={`bg-white rounded-xl border border-slate-200 p-5`}>
      <p className="text-sm text-slate-500 mb-1">{label}</p>
      <p className={`text-3xl font-bold ${color || 'text-slate-800'}`}>{value ?? '—'}</p>
    </div>
  )
}

export default function AdminDashboard() {
  const [stats, setStats] = useState(null)
  const [certs, setCerts] = useState([])
  const [flagged, setFlagged] = useState([])
  const [tab, setTab] = useState('stats')
  const [revokeId, setRevokeId] = useState('')
  const [revokeReason, setRevokeReason] = useState('')
  const [revokeMsg, setRevokeMsg] = useState('')

  useEffect(() => {
    adminStats().then(r => setStats(r.data))
    adminCertificates().then(r => setCerts(r.data.results || []))
    adminFlagged().then(r => setFlagged(r.data.flagged_events || []))
  }, [])

  const handleRevoke = async () => {
    if (!revokeId || !revokeReason) return
    try {
      await adminRevoke(revokeId, revokeReason)
      setRevokeMsg(`Certificate ${revokeId.slice(0,8)}... revoked.`)
      setRevokeId(''); setRevokeReason('')
    } catch(e) {
      setRevokeMsg('Revocation failed: ' + (e.response?.data?.detail || e.message))
    }
  }

  const TABS = ['stats','certificates','flagged','revoke']

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold text-slate-900">Admin Dashboard</h1>

      <div className="flex gap-2 border-b border-slate-200">
        {TABS.map(t => (
          <button key={t} onClick={() => setTab(t)}
            className={`px-4 py-2 text-sm font-medium capitalize ${tab===t ? 'border-b-2 border-blue-600 text-blue-700' : 'text-slate-500 hover:text-slate-700'}`}>
            {t}
          </button>
        ))}
      </div>

      {tab === 'stats' && stats && (
        <div className="space-y-6">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <StatCard label="Valid" value={stats.by_result?.valid || 0} color="text-green-700" />
            <StatCard label="Tampered" value={stats.by_result?.tampered || 0} color="text-amber-700" />
            <StatCard label="Not Found" value={stats.by_result?.not_found || 0} />
            <StatCard label="Flagged Events" value={stats.flagged_events} color="text-red-700" />
          </div>
          <div className="bg-white rounded-xl border border-slate-200 p-6">
            <h2 className="font-semibold text-slate-800 mb-4">By Method (last {stats.period_days} days)</h2>
            <dl className="space-y-1 text-sm">
              {Object.entries(stats.by_method || {}).map(([m,c]) => (
                <div key={m} className="flex justify-between">
                  <dt className="text-slate-500 capitalize">{m.replace('_',' ')}</dt>
                  <dd className="font-medium text-slate-800">{c}</dd>
                </div>
              ))}
            </dl>
          </div>
        </div>
      )}

      {tab === 'certificates' && (
        <div className="bg-white rounded-xl border border-slate-200 overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-slate-50 border-b border-slate-200">
              <tr>
                {['Certificate ID','Standard','Issued','Status'].map(h => (
                  <th key={h} className="text-left px-4 py-3 text-slate-500 font-medium">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {certs.map(c => (
                <tr key={c.certificate_id} className="border-b border-slate-100 hover:bg-slate-50">
                  <td className="px-4 py-3 font-mono text-xs">{c.certificate_id.slice(0,8)}...</td>
                  <td className="px-4 py-3">{c.wipe_standard}</td>
                  <td className="px-4 py-3">{formatDate(c.generated_at)}</td>
                  <td className="px-4 py-3">
                    {c.revoked ? <span className="text-red-600 text-xs font-medium">REVOKED</span>
                     : <span className="text-green-600 text-xs font-medium">ACTIVE</span>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {certs.length === 0 && <p className="text-center py-8 text-slate-400 text-sm">No certificates registered.</p>}
        </div>
      )}

      {tab === 'flagged' && (
        <div className="bg-white rounded-xl border border-slate-200 overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-slate-50 border-b border-slate-200">
              <tr>
                {['Certificate ID','Method','Result','Time','Reason'].map(h => (
                  <th key={h} className="text-left px-4 py-3 text-slate-500 font-medium">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {flagged.map(e => (
                <tr key={e.id} className="border-b border-slate-100">
                  <td className="px-4 py-3 font-mono text-xs">{e.certificate_id?.slice(0,8) || 'N/A'}...</td>
                  <td className="px-4 py-3">{e.method}</td>
                  <td className="px-4 py-3"><StatusBadge status={e.result} /></td>
                  <td className="px-4 py-3">{formatDate(e.verified_at)}</td>
                  <td className="px-4 py-3 text-xs text-red-600">{e.flag_reason}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {flagged.length === 0 && <p className="text-center py-8 text-slate-400 text-sm">No flagged events.</p>}
        </div>
      )}

      {tab === 'revoke' && (
        <div className="bg-white rounded-xl border border-slate-200 p-6 space-y-4 max-w-lg">
          <h2 className="font-semibold text-slate-800">Revoke Certificate</h2>
          <input type="text" value={revokeId} onChange={e => setRevokeId(e.target.value)}
            placeholder="Certificate UUID"
            className="w-full border border-slate-300 rounded-lg px-4 py-2.5 text-sm font-mono focus:outline-none focus:ring-2 focus:ring-red-500" />
          <textarea value={revokeReason} onChange={e => setRevokeReason(e.target.value)}
            placeholder="Reason for revocation (required)"
            rows={3}
            className="w-full border border-slate-300 rounded-lg px-4 py-2.5 text-sm focus:outline-none focus:ring-2 focus:ring-red-500 resize-none" />
          {revokeMsg && <p className={`text-sm ${revokeMsg.includes('failed') ? 'text-red-600' : 'text-green-600'}`}>{revokeMsg}</p>}
          <button onClick={handleRevoke} disabled={!revokeId || !revokeReason}
            className="bg-red-600 text-white px-5 py-2.5 rounded-lg text-sm font-medium hover:bg-red-700 disabled:opacity-50">
            Revoke Certificate
          </button>
        </div>
      )}
    </div>
  )
}