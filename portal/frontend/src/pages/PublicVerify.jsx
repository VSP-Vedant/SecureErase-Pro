import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import VerifyTabs from '../components/VerifyTabs'
import StatusBadge from '../components/StatusBadge'
import ComplianceBadgeGrid from '../components/ComplianceBadgeGrid'
import { formatDate } from '../utils/statusHelpers'

export default function PublicVerify() {
  const [result, setResult] = useState(null)
  const navigate = useNavigate()

  const handleResult = (data) => {
    setResult(data)
    if (data.certificate_id) {
      navigate(`/cert/${data.certificate_id}`, { state: { result: data } })
    }
  }

  return (
    <div className="max-w-2xl mx-auto space-y-8">
      <div className="text-center space-y-2">
        <h1 className="text-3xl font-bold text-slate-900">Verify Erasure Certificate</h1>
        <p className="text-slate-500">
          Verify any SecureErase Pro certificate using its ID, JSON file, or QR code.
        </p>
      </div>

      <VerifyTabs onResult={handleResult} />

      <div className="bg-white rounded-xl border border-slate-200 p-6 text-sm text-slate-600 space-y-2">
        <p className="font-medium text-slate-800">Offline Verification</p>
        <p>
          Every certificate is independently verifiable using the issuer's public key — no internet required.
          Download the public key from the URL embedded in your certificate's <code className="text-xs bg-slate-100 px-1 rounded">issuer.public_key_url</code> field
          and verify the cryptographic signature using OpenSSL or any standard tool.
        </p>
      </div>
    </div>
  )
}