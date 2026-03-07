import { useEffect, useState } from 'react'
import { useParams, useLocation } from 'react-router-dom'
import { verifyById } from '../utils/api'
import StatusBadge from '../components/StatusBadge'
import ComplianceBadgeGrid from '../components/ComplianceBadgeGrid'
import { formatDate } from '../utils/statusHelpers'

function InfoRow({ label, value, mono }) {
  return (
    <div className="flex gap-4 py-2 border-b border-slate-100 last:border-0">
      <dt className="w-40 text-sm text-slate-500 shrink-0">{label}</dt>
      <dd className={`text-sm text-slate-800 break-all ${mono ? 'font-mono text-xs' : ''}`}>
        {value ?? '—'}
      </dd>
    </div>
  )
}

export default function CertDetail() {
  const { id } = useParams()
  const location = useLocation()
  const [data, setData] = useState(location.state?.result || null)
  const [loading, setLoading] = useState(!data)
  const [error, setError] = useState('')

  useEffect(() => {
    if (!data) {
      verifyById(id)
        .then(r => setData(r.data))
        .catch(() => setError('Certificate not found or verification failed.'))
        .finally(() => setLoading(false))
    }
  }, [id])

  if (loading) return <div className="text-center py-20 text-slate-400">Verifying...</div>
  if (error) return <div className="text-center py-20 text-red-500">{error}</div>
  if (!data) return null

  const cert = data.certificate || {}

  return (
    <div className="max-w-3xl mx-auto space-y-6">
      <div className="bg-white rounded-xl border border-slate-200 p-6">
        <div className="flex items-start justify-between mb-6">
          <div>
            <h1 className="text-xl font-bold text-slate-900 mb-1">Erasure Certificate</h1>
            <p className="font-mono text-xs text-slate-400">{id}</p>
          </div>
          <StatusBadge status={data.status} size="lg" />
        </div>

        <p className="text-sm text-slate-600 bg-slate-50 rounded-lg p-3 mb-6">{data.message}</p>

        <dl>
          <InfoRow label="Issued At" value={formatDate(cert.generated_at)} />
          <InfoRow label="Issuer" value={cert.issuer_org} />
          <InfoRow label="Wipe Standard" value={cert.wipe_standard} />
          <InfoRow label="Passes" value={cert.passes_completed} />
          <InfoRow label="Wipe Verified" value={cert.verified ? 'Yes ✅' : 'No ❌'} />
          {data.algorithm && <InfoRow label="Signature Algorithm" value={data.algorithm} mono />}
        </dl>
      </div>

      {cert.compliance_frameworks?.length > 0 && (
        <div className="bg-white rounded-xl border border-slate-200 p-6">
          <h2 className="font-semibold text-slate-800 mb-4">Compliance Standards Satisfied</h2>
          <ComplianceBadgeGrid frameworks={cert.compliance_frameworks} />
        </div>
      )}

      {data.status === 'valid' && (
        <div className="bg-green-50 border border-green-200 rounded-xl p-4 text-sm text-green-800">
          This certificate's digital signature has been cryptographically verified.
          The erasure record has not been modified since it was signed.
        </div>
      )}

      {data.status === 'tampered' && (
        <div className="bg-amber-50 border border-amber-200 rounded-xl p-4 text-sm text-amber-800">
          <strong>Warning:</strong> This certificate's signature does not match its contents.
          The document may have been modified after signing.
          {data.tamper_details && <p className="mt-1 font-mono text-xs">{data.tamper_details}</p>}
        </div>
      )}

      {data.status === 'revoked' && cert.revocation && (
        <div className="bg-red-50 border border-red-200 rounded-xl p-4 text-sm text-red-800">
          <strong>Revoked</strong> on {formatDate(cert.revocation.revoked_at)}.
          Reason: {cert.revocation.reason}
        </div>
      )}
    </div>
  )
}