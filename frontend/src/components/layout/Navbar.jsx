import { Link, useLocation } from 'react-router-dom'
import { Shield, Activity, FileText, Clock } from 'lucide-react'
import BrandLogo from './BrandLogo'

const navItems = [
  { path: '/', label: 'Investigate', icon: Shield },
  { path: '/dashboard', label: 'Dashboard', icon: Activity },
  { path: '/report', label: 'Report', icon: FileText },
  { path: '/history', label: 'History', icon: Clock },
]

const ACTIVE_NAV_LINK_CLASSES =
  'flex items-center gap-2 px-4 py-2 rounded-lg border border-blue-400/30 text-sm font-semibold bg-sentinel-accent text-white shadow-sm shadow-blue-500/20 transition-all active:scale-[0.98]'

const INACTIVE_NAV_LINK_CLASSES =
  'flex items-center gap-2 px-4 py-2 rounded-lg border border-transparent text-sm font-medium text-slate-300 hover:text-white hover:bg-white/5 hover:border-blue-500/20 transition-all active:scale-[0.98]'

export default function Navbar() {
  const location = useLocation()

  return (
    <nav className="sticky top-0 z-50 border-b border-white/10 bg-sentinel-surface/95 px-6 py-3 shadow-lg shadow-black/25 backdrop-blur">
      <div className="max-w-7xl mx-auto flex items-center justify-between gap-6">
        <div className="flex items-center gap-3 rounded-xl border border-sentinel-border/60 bg-sentinel-bg/40 px-3 py-2">
          <BrandLogo variant="mark" className="h-9 w-9 shrink-0" />
          <div className="flex items-baseline gap-3">
            <span className="text-xl font-bold tracking-tight text-white">
              Splunk <span className="text-sentinel-accent">Sentinel</span>
            </span>
            <span className="text-xs text-sentinel-muted border border-sentinel-border rounded px-2 py-0.5">
              Agentic SOC
            </span>
          </div>
        </div>
        <div className="flex items-center gap-1 bg-blue-950/30 border border-blue-500/20 rounded-xl p-1 shadow-sm shadow-black/30">
          {navItems.map(({ path, label, icon: Icon }) => {
            const isActive = location.pathname === path
            return (
              <Link
                key={path}
                to={path}
                className={
                  isActive
                    ? ACTIVE_NAV_LINK_CLASSES
                    : INACTIVE_NAV_LINK_CLASSES
                }
              >
                <Icon className="w-4 h-4" />
                {label}
              </Link>
            )
          })}
        </div>
      </div>
    </nav>
  )
}
