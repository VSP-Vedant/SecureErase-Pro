import axios from 'axios'
const BASE = import.meta.env.VITE_API_BASE_URL || ''
const api = axios.create({ baseURL: BASE, timeout: 30000 })
api.interceptors.request.use(config => {
  const token = localStorage.getItem('sep_token')
  if (token) config.headers['Authorization'] = `Bearer ${token}`
  return config
})
api.interceptors.response.use(r => r, err => {
  if (err.response?.status === 401) {
    localStorage.removeItem('sep_token')
    window.location.href = '/login'
  }
  return Promise.reject(err)
})
export default api
export const verifyById = (id) => api.get(`/api/v1/verify/${id}`)
export const verifyByUpload = (file) => {
  const fd = new FormData(); fd.append('file', file)
  return api.post('/api/v1/verify/upload', fd)
}
export const verifyByQRPayload = (payload) => {
  const fd = new FormData(); fd.append('payload', payload)
  return api.post('/api/v1/verify/qr', fd)
}
export const login = (email, password) =>
  api.post('/api/v1/auth/login', { email, password })
export const verifyTOTP = (code) =>
  api.post('/api/v1/auth/totp/verify', { code })
export const adminStats = (days = 30) => api.get(`/api/v1/admin/stats?days=${days}`)
export const adminCertificates = (page = 1) => api.get(`/api/v1/admin/certificates?page=${page}`)
export const adminFlagged = () => api.get('/api/v1/admin/flagged')
export const adminRevoke = (certId, reason) =>
  api.delete(`/api/v1/admin/certificates/${certId}`, { data: { reason } })