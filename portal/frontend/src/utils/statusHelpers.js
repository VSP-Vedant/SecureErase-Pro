export const STATUS_LABELS = {
  valid:'Valid', invalid:'Invalid', tampered:'Tampered',
  not_found:'Not Found', revoked:'Revoked', error:'Error',
}
export const STATUS_ICONS = {
  valid:'✅', invalid:'❌', tampered:'⚠️',
  not_found:'🔍', revoked:'🚫', error:'⛔',
}
export const formatDate = (iso) => iso
  ? new Date(iso).toLocaleString(undefined, { dateStyle:'medium', timeStyle:'short' })
  : '—'