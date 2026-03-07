const FRAMEWORK_COLORS = {
  'NIST SP 800-88 Rev.1': 'bg-blue-100 text-blue-800',
  'DoD 5220.22-M': 'bg-indigo-100 text-indigo-800',
  'Gutmann': 'bg-violet-100 text-violet-800',
  'GDPR': 'bg-emerald-100 text-emerald-800',
  'HIPAA': 'bg-teal-100 text-teal-800',
  'ISO/IEC 27001:2022': 'bg-cyan-100 text-cyan-800',
  'PCI-DSS v4.0': 'bg-orange-100 text-orange-800',
  'SOC 2': 'bg-amber-100 text-amber-800',
}

const DEFAULT_COLOR = 'bg-slate-100 text-slate-700'

export default function ComplianceBadgeGrid({ frameworks }) {
  if (!frameworks || frameworks.length === 0) return null
  return (
    <div className="flex flex-wrap gap-2">
      {frameworks.map(fw => (
        <span
          key={fw}
          className={`text-xs font-medium px-2.5 py-1 rounded-full ${FRAMEWORK_COLORS[fw] || DEFAULT_COLOR}`}
        >
          {fw}
        </span>
      ))}
    </div>
  )
}