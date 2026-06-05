import { useState, useEffect, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import { useInvestigation } from '../store/InvestigationContext'
import AgentStatusPanel from '../components/investigation/AgentStatusPanel'
import KillChainGraph from '../components/investigation/KillChainGraph'
import EventFeed from '../components/investigation/EventFeed'
import ConfidenceChart from '../components/investigation/ConfidenceChart'

const SEVERITY_STYLES = {
  CRITICAL: { dot: 'bg-red-400', text: 'text-red-400', border: 'border-red-500/30', badge: 'bg-red-900/20 text-red-300 border-red-500/30' },
  HIGH:     { dot: 'bg-orange-400', text: 'text-orange-400', border: 'border-orange-500/30', badge: 'bg-orange-900/20 text-orange-300 border-orange-500/30' },
  MEDIUM:   { dot: 'bg-amber-400', text: 'text-amber-400', border: 'border-amber-500/30', badge: 'bg-amber-900/20 text-amber-300 border-amber-500/30' },
  LOW:      { dot: 'bg-green-400', text: 'text-green-400', border: 'border-green-500/30', badge: 'bg-green-900/20 text-green-300 border-green-500/30' },
  UNKNOWN:  { dot: 'bg-slate-400', text: 'text-slate-400', border: 'border-slate-500/30', badge: 'bg-slate-900/20 text-slate-300 border-slate-500/30' },
}

const CLASSIFICATION_LABELS = {
  APT: 'APT',
  RANSOMWARE: 'Ransomware',
  INSIDER_THREAT: 'Insider Threat',
  BRUTE_FORCE: 'Brute Force',
  UNKNOWN: 'Unknown',
}

let lastRedirectedId = null;

export default function DashboardPage() {
  const { state } = useInvestigation()
  const navigate = useNavigate()
  const [recentInvestigations, setRecentInvestigations] = useState([])
  const [loadingRecent, setLoadingRecent] = useState(true)

  const fetchRecent = useCallback(async () => {
    try {
      const res = await fetch('/api/investigations/history?page=1&limit=3')
      if (!res.ok) throw new Error('Failed to fetch')
      const data = await res.json()
      setRecentInvestigations(data.investigations || [])
    } catch {
      setRecentInvestigations([])
    } finally {
      setLoadingRecent(false)
    }
  }, [])

  // Redirect to report when complete (ONLY ONCE per investigation)
  useEffect(() => {
    if (state.status === 'complete' && state.result && lastRedirectedId !== state.investigationId) {
      lastRedirectedId = state.investigationId;
      const timer = setTimeout(() => navigate('/report'), 1500);
      return () => clearTimeout(timer);
    }
  }, [state.status, state.result, navigate, state.investigationId])

  useEffect(() => {
    if (state.status === 'idle') {
      fetchRecent()
    }
  }, [state.status, fetchRecent])

  if (state.status === 'idle') {
    return (
      <div className="min-h-[calc(100vh-57px)] px-6 py-10">
        <div className="max-w-5xl mx-auto">

          {/* Header */}
          <div className="flex items-center justify-between mb-8">
            <div>
              <h1 className="text-2xl font-bold text-white tracking-tight">SOC Operations Center</h1>
              <p className="text-sm text-sentinel-muted mt-1">No active investigation — system ready</p>
            </div>
            <button
              onClick={() => navigate('/')}
              className="flex items-center gap-2 px-4 py-2 bg-sentinel-accent hover:bg-blue-500 text-white rounded-lg text-sm font-medium transition-colors"
            >
              Start Investigation
            </button>
          </div>

          {/* Recent Investigations */}
          <div className="bg-sentinel-surface border border-sentinel-border rounded-xl p-6" style={{ borderTop: '2px solid #3b82f6' }}>
            <div className="flex items-center justify-between mb-5">
              <div className="flex items-center gap-2">
                <div className="w-2 h-4 rounded-sm bg-sentinel-accent" />
                <h2 className="text-sm font-bold text-white tracking-wide">Recent Investigations</h2>
              </div>
              <button
                onClick={() => navigate('/history')}
                className="text-xs text-sentinel-accent hover:text-blue-300 transition-colors"
              >
                View all →
              </button>
            </div>
            {loadingRecent && (
              <div className="flex items-center gap-2 py-8 justify-center">
                <div className="w-4 h-4 border-2 border-sentinel-accent border-t-transparent rounded-full animate-spin" />
                <span className="text-xs text-sentinel-muted">Loading recent investigations...</span>
              </div>
            )}

            {!loadingRecent && recentInvestigations.length === 0 && (
              <div className="py-8 text-center">
                <p className="text-sm text-sentinel-muted">No investigations yet.</p>
                <p className="text-xs text-sentinel-muted mt-1">Run your first investigation to see results here.</p>
              </div>
            )}

            {!loadingRecent && recentInvestigations.length > 0 && (
              <div className="space-y-3">
                {recentInvestigations.map((inv) => {
                  const sev = inv.severity?.toUpperCase() || 'UNKNOWN'
                  const classKey = inv.classification?.toUpperCase().replace(/[^A-Z_]/g, '_') || 'UNKNOWN'
                  const classLabel = CLASSIFICATION_LABELS[classKey] || inv.classification || 'Unknown'
                  const confidencePct = Math.round((inv.confidence || 0) * 100)
                  const timeAgo = inv.created_at ? new Date(inv.created_at).toLocaleDateString() : '—'
                  return (
                    <button
                      key={inv.investigation_id}
                      onClick={() => navigate(`/report/${inv.investigation_id}`)}
                      className="w-full text-left bg-sentinel-bg border border-sentinel-border rounded-lg px-4 py-3 hover:border-sentinel-accent/50 transition-colors"
                    >
                      <div className="flex items-center justify-between gap-4">
                        <div className="flex items-center gap-3 min-w-0">
                          {sev === 'CRITICAL' && (
                            <div className="w-2 h-2 rounded-full flex-shrink-0 bg-red-400" />
                          )}
                          {sev === 'HIGH' && (
                            <div className="w-2 h-2 rounded-full flex-shrink-0 bg-orange-400" />
                          )}
                          {sev === 'MEDIUM' && (
                            <div className="w-2 h-2 rounded-full flex-shrink-0 bg-amber-400" />
                          )}
                          {sev === 'LOW' && (
                            <div className="w-2 h-2 rounded-full flex-shrink-0 bg-green-400" />
                          )}
                          {!SEVERITY_STYLES[sev] && (
                            <div className="w-2 h-2 rounded-full flex-shrink-0 bg-slate-400" />
                          )}
                          {sev === 'UNKNOWN' && (
                            <div className="w-2 h-2 rounded-full flex-shrink-0 bg-slate-400" />
                          )}
                          <div className="min-w-0">
                            <p className="text-xs text-white font-medium truncate">{inv.trigger_text || 'No trigger text'}</p>
                            <p className="text-[10px] text-sentinel-muted mt-0.5">{inv.investigation_id} · {timeAgo}</p>
                          </div>
                        </div>
                        <div className="flex items-center gap-2 flex-shrink-0">
                          {sev === 'CRITICAL' && (
                            <span className="text-[10px] font-bold px-2 py-0.5 rounded border bg-red-900/20 text-red-300 border-red-500/30">{sev}</span>
                          )}
                          {sev === 'HIGH' && (
                            <span className="text-[10px] font-bold px-2 py-0.5 rounded border bg-orange-900/20 text-orange-300 border-orange-500/30">{sev}</span>
                          )}
                          {sev === 'MEDIUM' && (
                            <span className="text-[10px] font-bold px-2 py-0.5 rounded border bg-amber-900/20 text-amber-300 border-amber-500/30">{sev}</span>
                          )}
                          {sev === 'LOW' && (
                            <span className="text-[10px] font-bold px-2 py-0.5 rounded border bg-green-900/20 text-green-300 border-green-500/30">{sev}</span>
                          )}
                          {!SEVERITY_STYLES[sev] && (
                            <span className="text-[10px] font-bold px-2 py-0.5 rounded border bg-slate-900/20 text-slate-300 border-slate-500/30">{sev}</span>
                          )}
                          {sev === 'UNKNOWN' && (
                            <span className="text-[10px] font-bold px-2 py-0.5 rounded border bg-slate-900/20 text-slate-300 border-slate-500/30">{sev}</span>
                          )}
                          <span className="text-[10px] text-sentinel-muted border border-sentinel-border rounded px-2 py-0.5">{classLabel}</span>
                          <span className="text-xs font-bold text-sentinel-accent">{confidencePct}%</span>
                        </div>
                      </div>
                    </button>
                  )
                })}
              </div>
            )}
          </div>

        </div>
      </div>
    )
  }

  return (
    <div className="max-w-7xl mx-auto px-6 py-6">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h2 className="text-lg font-semibold text-white">Live Investigation</h2>
          <p className="text-xs text-sentinel-muted font-mono mt-1">
            {state.investigationId}
          </p>
        </div>
        <div className="flex items-center gap-3">
          {state.status === 'running' && (
            <span className="flex items-center gap-2 text-sm text-sentinel-warning">
              <span className="w-2 h-2 bg-sentinel-warning rounded-full animate-pulse" />
              Investigating...
            </span>
          )}
          {state.status === 'complete' && (
            <span className="flex items-center gap-2 text-sm text-sentinel-success">
              <span className="w-2 h-2 bg-sentinel-success rounded-full" />
              Complete - loading report...
            </span>
          )}
        </div>
      </div>

      {/* Main grid */}
      <div className="grid grid-cols-12 gap-5">
        {/* Left: Agent status */}
        <div className="col-span-12 lg:col-span-3">
          <AgentStatusPanel />
        </div>

        {/* Center: Kill chain graph */}
        <div className="col-span-12 lg:col-span-6">
          <KillChainGraph />
        </div>

        {/* Right: Event feed */}
        <div className="col-span-12 lg:col-span-3">
          <EventFeed />
        </div>

        {/* Bottom: Confidence chart */}
        <div className="col-span-12">
          <ConfidenceChart />
        </div>
      </div>
    </div>
  )
}
