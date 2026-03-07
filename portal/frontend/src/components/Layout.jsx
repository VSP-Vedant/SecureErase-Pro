import { Outlet, Link, useNavigate } from 'react-router-dom'

export default function Layout() {
  const navigate = useNavigate()
  const token = localStorage.getItem('sep_token')

  return (
    <div className="min-h-screen bg-slate-50">
      <header className="bg-white border-b border-slate-200 shadow-sm">
        <div className="max-w-5xl mx-auto px-4 py-3 flex items-center justify-between">
          <Link to="/" className="flex items-center gap-2">
            <div className="w-8 h-8 bg-blue-600 rounded flex items-center justify-center text-white font-bold text-sm">SE</div>
            <span className="font-semibold text-slate-800">SecureErase Pro</span>
          </Link>
          <nav className="flex items-center gap-4 text-sm">
            <Link to="/" className="text-slate-600 hover:text-blue-600">Verify</Link>
            {token ? (
              <>
                <Link to="/enterprise" className="text-slate-600 hover:text-blue-600">Enterprise</Link>
                <button
                  onClick={() => { localStorage.removeItem('sep_token'); navigate('/') }}
                  className="text-slate-600 hover:text-red-600"
                >Logout</button>
              </>
            ) : (
              <Link to="/login" className="bg-blue-600 text-white px-3 py-1.5 rounded hover:bg-blue-700">Login</Link>
            )}
          </nav>
        </div>
      </header>
      <main className="max-w-5xl mx-auto px-4 py-8">
        <Outlet />
      </main>
      <footer className="border-t border-slate-200 bg-white mt-16 py-6 text-center text-xs text-slate-400">
        SecureErase Pro — Secure Data Sanitisation Platform &copy; {new Date().getFullYear()}
      </footer>
    </div>
  )
}