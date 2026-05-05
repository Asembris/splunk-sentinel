import { Link, useLocation } from 'react-router-dom'
import { Shield, Activity, FileText, Clock } from 'lucide-react'

const navItems = [
  { path: '/', label: 'Investigate', icon: Shield },
  { path: '/dashboard', label: 'Dashboard', icon: Activity },
  { path: '/report', label: 'Report', icon: FileText },
  { path: '/history', label: 'History', icon: Clock },
]

export default function Navbar() {
  const location = useLocation()

  return (
    <nav className="border-b border-sentinel-border bg-sentinel-surface px-6 py-3">
      <div className="max-w-7xl mx-auto flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Shield className="text-sentinel-accent w-7 h-7" />
          <span className="text-xl font-bold tracking-tight text-white">
            Splunk <span className="text-sentinel-accent">Sentinel</span>
          </span>
          <span className="text-xs text-sentinel-muted ml-2 border border-sentinel-border rounded px-2 py-0.5">
            Agentic SOC
          </span>
        </div>
        <div className="flex items-center gap-1">
          {navItems.map(({ path, label, icon: Icon }) => (
            <Link
              key={path}
              to={path}
              className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
                location.pathname === path
                  ? 'bg-sentinel-accent text-white'
                  : 'text-sentinel-muted hover:text-white hover:bg-sentinel-border'
              }`}
            >
              <Icon className="w-4 h-4" />
              {label}
            </Link>
          ))}
        </div>
      </div>
    </nav>
  )
}
