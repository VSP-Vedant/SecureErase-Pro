import { useState, useEffect } from 'react'
import { verifyById } from '../utils/api'
import VerifyTabs from '../components/VerifyTabs'
import StatusBadge from '../components/StatusBadge'
import ComplianceBadgeGrid from '../components/ComplianceBadgeGrid'
import { formatDate } from '../utils/statusHelpers'

function DetailSection({ title, children }) {
  return (
    <div className="bg-white rounded-xl border border-slate-200 p-6">
      <h2 className="font-semibold text-slate-800 mb-4">{title}</h2>
      {children}
    </div>
  )
}

function InfoRow({ label, value, mono }) {
  return (
    <div className="flex gap-4 py-1.5 border-b border-slate-100 last:border-0">
      <dt className="w-44 text-sm text-slate-500 shrink-0">{label}</dt>
      <dd className={`text-sm text-slate-800 break-all ${mono ? 'font-mono text-xs' : ''}`}>{value ?? '—'}</dd>
    </div>
  )
}

export default function EnterpriseDashboard() {
  const [result, setResult] = useState(null)

  const cert = result?.certificate || {}
  const operator = cert.operator || {}
  const target = cert.target || {}

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-slate-900">Enterprise Verification</h1>
        {result && <StatusBadge status={result.status} size="lg" />}
      </div>

      <VerifyTabs onResult={setResult} />

      {result && (
        <div className="space-y-4">
          <DetailSection title="Operator Details">
            <dl>
              <InfoRow label="Username" value={operator.username} />
              <InfoRow label="Hostname" value={operator.hostname} />
              <InfoRow label="IP Address" value={operator.ip_address} mono />
              <InfoRow label="OS" value={operator.os} />
              <InfoRow label="App Version" value={operator.app_version} mono />
            </dl>
          </DetailSection>

          <DetailSection title="Target">
            <dl>
              <InfoRow label="Path" value={target.path} mono />
              <InfoRow label="Type" value={target.type} />
              <InfoRow label="Size" value={target.size_bytes != null ? `${target.size_bytes.toLocaleString()} bytes` : null} />
              <InfoRow label="File Count" value={target.file_count} />
              <InfoRow label="SHA-256 (before)" value={cert.sha256_before} mono />
              <InfoRow label="SHA3-256 (before)" value={cert.sha3_256_before} mono />
              <InfoRow label="SHA-256 (after)" value={cert.sha256_after} mono />
              <InfoRow label="SHA3-256 (after)" value={cert.sha3_256_after} mono />
            </dl>
          </DetailSection>

          {cert.pass_detail?.length > 0 && (
            <DetailSection title="Wipe Pass Log">
              <table className="w-full text-sm">
                <thead><tr className="text-left text-slate-500 border-b border-slate-200">
                  <th className="pb-2 pr-4">#</th>
                  <th className="pb-2 pr-4">Pattern</th>
                  <th className="pb-2">Verified</th>
                </tr></thead>
                <tbody>
                  {cert.pass_detail.map(p => (
                    <tr key={p.pass_number} className="border-b border-slate-100 last:border-0">
                      <td className="py-1.5 pr-4">{p.pass_number}</td>
                      <td className="py-1.5 pr-4 font-mono text-xs">{p.pattern}</td>
                      <td className="py-1.5">{p.verified ? '✅' : '❌'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </DetailSection>
          )}

          {cert.compliance_frameworks?.length > 0 && (
            <DetailSection title="Compliance Standards">
              <ComplianceBadgeGrid frameworks={cert.compliance_frameworks} />
            </DetailSection>
          )}

          {cert.audit_chain && (
            <DetailSection title="Audit Chain">
              <dl>
                <InfoRow label="Chain Position" value={cert.audit_chain.chain_position} />
                <InfoRow label="Previous Cert Hash" value={cert.audit_chain.previous_certificate_hash} mono />
              </dl>
            </DetailSection>
          )}
        </div>
      )}
    </div>
  )
}