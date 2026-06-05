import { useState, useEffect, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import { useInvestigation } from '../store/InvestigationContext'
import AgentStatusPanel from '../components/investigation/AgentStatusPanel'
import KillChainGraph from '../components/investigation/KillChainGraph'
import EventFeed from '../components/investigation/EventFeed'
import ConfidenceChart from '../components/investigation/ConfidenceChart'

const CLASSIFICATION_LABELS = {
  APT: 'APT',
  RANSOMWARE: 'Ransomware',
  INSIDER_THREAT: 'Insider Threat',
  BRUTE_FORCE: 'Brute Force',
  UNKNOWN: 'Unknown',
}

function normalizeSeverity(value) {
  const severity = String(value || 'UNKNOWN').toUpperCase()
  if (severity === 'CRITICAL') return 'CRITICAL'
  if (severity === 'HIGH') return 'HIGH'
  if (severity === 'MEDIUM') return 'MEDIUM'
  if (severity === 'LOW') return 'LOW'
  return 'UNKNOWN'
}

function normalizeClassification(value) {
  return String(value || 'UNKNOWN').toUpperCase().replace(/[^A-Z_]/g, '_')
}

function severityRank(severity) {
  if (severity === 'CRITICAL') return 4
  if (severity === 'HIGH') return 3
  if (severity === 'MEDIUM') return 2
  if (severity === 'LOW') return 1
  return 0
}

function getHighestSeverity(investigations) {
  return investigations.reduce((highest, investigation) => {
    const severity = normalizeSeverity(investigation.severity)
    return severityRank(severity) > severityRank(highest) ? severity : highest
  }, 'UNKNOWN')
}

function formatHistoryDate(value) {
  if (!value) return 'Unknown date'
  return new Date(value).toLocaleString()
}

function SeverityBadge({ severity }) {
  if (severity === 'CRITICAL') {
    return (
      <span className="text-[10px] font-bold px-2 py-0.5 rounded border bg-red-900/20 text-red-300 border-red-500/30">
        CRITICAL
      </span>
    )
  }
  if (severity === 'HIGH') {
    return (
      <span className="text-[10px] font-bold px-2 py-0.5 rounded border bg-orange-900/20 text-orange-300 border-orange-500/30">
        HIGH
      </span>
    )
  }
  if (severity === 'MEDIUM') {
    return (
      <span className="text-[10px] font-bold px-2 py-0.5 rounded border bg-amber-900/20 text-amber-300 border-amber-500/30">
        MEDIUM
      </span>
    )
  }
  if (severity === 'LOW') {
    return (
      <span className="text-[10px] font-bold px-2 py-0.5 rounded border bg-green-900/20 text-green-300 border-green-500/30">
        LOW
      </span>
    )
  }
  return (
    <span className="text-[10px] font-bold px-2 py-0.5 rounded border bg-slate-900/20 text-slate-300 border-slate-500/30">
      UNKNOWN
    </span>
  )
}

function SeverityValue({ severity }) {
  if (severity === 'CRITICAL') {
    return <div className="text-lg font-bold text-red-400">CRITICAL</div>
  }
  if (severity === 'HIGH') {
    return <div className="text-lg font-bold text-orange-400">HIGH</div>
  }
  if (severity === 'MEDIUM') {
    return <div className="text-lg font-bold text-amber-400">MEDIUM</div>
  }
  if (severity === 'LOW') {
    return <div className="text-lg font-bold text-green-400">LOW</div>
  }
  return <div className="text-lg font-bold text-slate-400">UNKNOWN</div>
}

function InvestigationCardContent({ investigation }) {
  const severity = normalizeSeverity(investigation.severity)
  const classKey = normalizeClassification(investigation.classification)
  const classLabel = CLASSIFICATION_LABELS[classKey] || investigation.classification || 'Unknown'
  const confidencePct = Math.round((investigation.confidence || 0) * 100)
  const createdAt = formatHistoryDate(investigation.created_at)
  const hasKillChainStages = (
    investigation.kill_chain_stages !== null
    && investigation.kill_chain_stages !== undefined
  )

  return (
    <div className="space-y-3">
      <div className="flex items-start justify-between gap-4">
        <div className="min-w-0">
          <p className="text-sm text-white font-semibold leading-snug truncate">
            {investigation.trigger_text || 'No trigger text'}
          </p>
          <p className="text-[10px] text-sentinel-muted mt-1 font-mono">
            {investigation.investigation_id} - {createdAt}
          </p>
        </div>
        <div className="flex items-center gap-2 flex-shrink-0">
          <SeverityBadge severity={severity} />
          <span className="text-[10px] text-sentinel-muted border border-sentinel-border rounded px-2 py-0.5">
            {classLabel}
          </span>
          <span className="text-sm font-bold text-sentinel-accent">
            {confidencePct}%
          </span>
        </div>
      </div>

      <div className="flex items-center gap-2 flex-wrap text-[10px] text-sentinel-muted">
        {investigation.patient_zero_ip && (
          <span className="rounded border border-sentinel-border bg-sentinel-bg px-2 py-1">
            Patient zero: {investigation.patient_zero_ip}
          </span>
        )}
        {hasKillChainStages && (
          <span className="rounded border border-sentinel-border bg-sentinel-bg px-2 py-1">
            {investigation.kill_chain_stages} kill chain stages
          </span>
        )}
        {investigation.containment_priority && (
          <span className="rounded border border-sentinel-border bg-sentinel-bg px-2 py-1">
            Containment: {investigation.containment_priority}
          </span>
        )}
        {investigation.escalate_to_human && (
          <span className="text-[10px] font-medium text-amber-300 border border-amber-500/30 bg-amber-900/20 rounded px-2 py-0.5">
            Escalation flagged
          </span>
        )}
        {investigation.analyst_rating && (
          <span className="rounded border border-sentinel-border bg-sentinel-bg px-2 py-1">
            Analyst: {investigation.analyst_rating}
          </span>
        )}
      </div>
    </div>
  )
}

function RecentInvestigationCard({ investigation, onClick }) {
  const severity = normalizeSeverity(investigation.severity)

  if (severity === 'CRITICAL') {
    return (
      <button
        type="button"
        onClick={onClick}
        className="w-full text-left bg-sentinel-bg border border-sentinel-border border-l-2 border-l-red-400 rounded-lg px-4 py-3 hover:border-sentinel-accent/50 transition-colors"
      >
        <InvestigationCardContent investigation={investigation} />
      </button>
    )
  }
  if (severity === 'HIGH') {
    return (
      <button
        type="button"
        onClick={onClick}
        className="w-full text-left bg-sentinel-bg border border-sentinel-border border-l-2 border-l-orange-400 rounded-lg px-4 py-3 hover:border-sentinel-accent/50 transition-colors"
      >
        <InvestigationCardContent investigation={investigation} />
      </button>
    )
  }
  if (severity === 'MEDIUM') {
    return (
      <button
        type="button"
        onClick={onClick}
        className="w-full text-left bg-sentinel-bg border border-sentinel-border border-l-2 border-l-amber-400 rounded-lg px-4 py-3 hover:border-sentinel-accent/50 transition-colors"
      >
        <InvestigationCardContent investigation={investigation} />
      </button>
    )
  }
  if (severity === 'LOW') {
    return (
      <button
        type="button"
        onClick={onClick}
        className="w-full text-left bg-sentinel-bg border border-sentinel-border border-l-2 border-l-green-400 rounded-lg px-4 py-3 hover:border-sentinel-accent/50 transition-colors"
      >
        <InvestigationCardContent investigation={investigation} />
      </button>
    )
  }
  return (
    <button
      type="button"
      onClick={onClick}
      className="w-full text-left bg-sentinel-bg border border-sentinel-border border-l-2 border-l-slate-400 rounded-lg px-4 py-3 hover:border-sentinel-accent/50 transition-colors"
    >
      <InvestigationCardContent investigation={investigation} />
    </button>
  )
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

  const recentCount = recentInvestigations.length
  const highestSeverity = getHighestSeverity(recentInvestigations)
  const escalationsCount = recentInvestigations.filter(
    (investigation) => investigation.escalate_to_human
  ).length
  const averageConfidence = recentCount > 0
    ? Math.round(
      recentInvestigations.reduce(
        (sum, investigation) => sum + ((investigation.confidence || 0) * 100),
        0
      ) / recentCount
    )
    : 0
  const lastSeen = recentInvestigations[0]?.created_at
    ? formatHistoryDate(recentInvestigations[0].created_at)
    : null

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
        <div className="max-w-6xl mx-auto">

          {/* Header */}
          <div className="bg-sentinel-surface border border-sentinel-border border-t-2 border-t-sentinel-accent rounded-xl p-5 shadow-lg mb-5">
            <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
              <div>
                <div className="flex items-center gap-2 mb-2">
                  <span className="h-2 w-2 rounded-full bg-sentinel-accent" />
                  <span className="text-[10px] font-bold text-sentinel-accent uppercase tracking-widest">
                    Operations Overview
                  </span>
                </div>
                <h1 className="text-2xl font-bold text-white tracking-tight">
                  SOC Operations Center
                </h1>
                <p className="text-sm text-sentinel-muted mt-1">
                  No active investigation. Recent activity is derived from investigation history.
                </p>
                {lastSeen && (
                  <p className="text-xs text-sentinel-muted mt-2">
                    Last investigation recorded: {lastSeen}
                  </p>
                )}
              </div>
              <div className="flex items-center gap-3 flex-shrink-0">
                <button
                  onClick={() => navigate('/')}
                  className="px-4 py-2 bg-sentinel-accent hover:bg-blue-500 text-white rounded-lg text-sm font-medium transition-colors"
                >
                  Start Investigation
                </button>
                <button
                  onClick={() => navigate('/history')}
                  className="px-4 py-2 bg-sentinel-bg border border-sentinel-border hover:border-sentinel-accent text-sentinel-muted hover:text-white rounded-lg text-sm font-medium transition-colors"
                >
                  View History
                </button>
              </div>
            </div>
          </div>

          {!loadingRecent && recentInvestigations.length > 0 && (
            <div className="grid grid-cols-1 md:grid-cols-3 gap-3 mb-5">
              <div className="bg-sentinel-surface border border-sentinel-border rounded-xl p-4">
                <SeverityValue severity={highestSeverity} />
                <div className="text-[10px] text-sentinel-muted uppercase tracking-wider mt-1">
                  Last 3 Highest Severity
                </div>
              </div>
              <div className="bg-sentinel-surface border border-sentinel-border rounded-xl p-4">
                <div className="text-lg font-bold text-red-400">
                  {escalationsCount}
                </div>
                <div className="text-[10px] text-sentinel-muted uppercase tracking-wider mt-1">
                  Last 3 Escalations
                </div>
              </div>
              <div className="bg-sentinel-surface border border-sentinel-border rounded-xl p-4">
                <div className="text-lg font-bold text-sentinel-accent">
                  {averageConfidence}%
                </div>
                <div className="text-[10px] text-sentinel-muted uppercase tracking-wider mt-1">
                  Last 3 Avg Confidence
                </div>
              </div>
            </div>
          )}

          {/* Recent Investigations */}
          <div className="bg-sentinel-surface border border-sentinel-border rounded-xl p-6" style={{ borderTop: '2px solid #3b82f6' }}>
            <div className="flex items-center justify-between mb-5">
              <div>
                <div className="flex items-center gap-2">
                  <div className="w-2 h-4 rounded-sm bg-sentinel-accent" />
                  <h2 className="text-sm font-bold text-white tracking-wide">
                    Recent Investigation Queue
                  </h2>
                </div>
                <p className="text-xs text-sentinel-muted mt-1">
                  Last 3 records from persisted investigation history.
                </p>
              </div>
              <button
                onClick={() => navigate('/history')}
                className="text-xs text-sentinel-accent hover:text-blue-300 transition-colors"
              >
                View History
              </button>
            </div>

            {loadingRecent && (
              <div className="space-y-3">
                <div className="bg-sentinel-bg border border-sentinel-border rounded-lg px-4 py-4">
                  <div className="h-3 w-2/3 rounded bg-sentinel-border/70 mb-3" />
                  <div className="h-2 w-1/3 rounded bg-sentinel-border/50 mb-4" />
                  <div className="flex gap-2">
                    <div className="h-5 w-20 rounded bg-sentinel-border/40" />
                    <div className="h-5 w-24 rounded bg-sentinel-border/40" />
                    <div className="h-5 w-16 rounded bg-sentinel-border/40" />
                  </div>
                </div>
                <div className="bg-sentinel-bg border border-sentinel-border rounded-lg px-4 py-4">
                  <div className="h-3 w-3/4 rounded bg-sentinel-border/70 mb-3" />
                  <div className="h-2 w-1/4 rounded bg-sentinel-border/50 mb-4" />
                  <div className="flex gap-2">
                    <div className="h-5 w-16 rounded bg-sentinel-border/40" />
                    <div className="h-5 w-28 rounded bg-sentinel-border/40" />
                    <div className="h-5 w-20 rounded bg-sentinel-border/40" />
                  </div>
                </div>
                <div className="bg-sentinel-bg border border-sentinel-border rounded-lg px-4 py-4">
                  <div className="h-3 w-1/2 rounded bg-sentinel-border/70 mb-3" />
                  <div className="h-2 w-1/3 rounded bg-sentinel-border/50 mb-4" />
                  <div className="flex gap-2">
                    <div className="h-5 w-24 rounded bg-sentinel-border/40" />
                    <div className="h-5 w-20 rounded bg-sentinel-border/40" />
                    <div className="h-5 w-16 rounded bg-sentinel-border/40" />
                  </div>
                </div>
              </div>
            )}

            {!loadingRecent && recentInvestigations.length === 0 && (
              <div className="py-10 text-center">
                <p className="text-sm text-sentinel-muted">
                  No investigations yet.
                </p>
                <p className="text-xs text-sentinel-muted mt-1 mb-4">
                  Run your first investigation to populate the operations queue.
                </p>
                <button
                  onClick={() => navigate('/')}
                  className="px-4 py-2 bg-sentinel-accent hover:bg-blue-500 text-white rounded-lg text-sm font-medium transition-colors"
                >
                  Start Investigation
                </button>
              </div>
            )}

            {!loadingRecent && recentInvestigations.length > 0 && (
              <div className="space-y-3">
                {recentInvestigations.map((inv) => (
                  <RecentInvestigationCard
                    key={inv.investigation_id}
                    investigation={inv}
                    onClick={() => navigate('/report/' + inv.investigation_id)}
                  />
                ))}
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
