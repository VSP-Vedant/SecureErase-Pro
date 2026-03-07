import { STATUS_ICONS, STATUS_LABELS } from '../utils/statusHelpers'

export default function StatusBadge({ status, size = 'md' }) {
  const sizeClass = size === 'lg' ? 'text-2xl px-5 py-2' : 'text-sm px-3 py-1'
  const colorMap = {
    valid: 'bg-green-100 text-green-800 border-green-300',
    invalid: 'bg-red-100 text-red-800 border-red-300',
    tampered: 'bg-amber-100 text-amber-800 border-amber-300',
    not_found: 'bg-gray-100 text-gray-600 border-gray-300',
    revoked: 'bg-red-100 text-red-700 border-red-300',
    error: 'bg-gray-100 text-gray-500 border-gray-300',
  }
  const cls = colorMap[status] || colorMap.error
  return (
    <span className={`inline-flex items-center gap-1.5 rounded-full border font-medium ${sizeClass} ${cls}`}>
      {STATUS_ICONS[status]} {STATUS_LABELS[status] || status}
    </span>
  )
}