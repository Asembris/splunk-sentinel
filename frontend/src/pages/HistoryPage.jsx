import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  Clock, Shield, ChevronRight, AlertTriangle,
  CheckCircle, XCircle, RefreshCw, Database
} from 'lucide-react'

const SEVERITY_STYLES = {
  CRITICAL: 'bg-red-500/20 text-red-400 border border-red-500/30',
  HIGH:     'bg-amber-500/20 text-amber-400 border border-amber-500/30',
  MEDIUM:   'bg-blue-500/20 text-blue-400 border border-blue-500/30',
  LOW:      'bg-green-500/20 text-green-400 border border-green-500/30',
}

const CLASSIFICATION_STYLES = {
  APT:            'bg-red-500/10 text-red-400',
  RANSOMWARE:     'bg-orange-500/10 text-orange-400',
  INSIDER_THREAT: 'bg-purple-500/10 text-purple-400',
  UNKNOWN:        'bg-gray-500/10 text-gray-400',
}

const CONFIDENCE_TIER = (confidence) => {
  if (confidence >= 0.90) return { label: 'AUTO-EXECUTE', color: 'text-red-400' }
  if (confidence >= 0.70) return { label: 'ANALYST REVIEW', color: 'text-amber-400' }
  if (confidence >= 0.60) return { label: 'MONITOR', color: 'text-blue-400' }
  return { label: 'ESCALATE', color: 'text-gray-400' }
}

const RATING_ICON = {
  correct:   <CheckCircle className="w-4 h-4 text-green-400" />,
  partial:   <AlertTriangle className="w-4 h-4 text-amber-400" />,
  incorrect: <XCircle className="w-4 h-4 text-red-400" />,
}

function formatTimeAgo(isoString) {
  const date = new Date(isoString)
  const now = new Date()
  const diffMs = now - date
  const diffMins = Math.floor(diffMs / 60000)
  const diffHours = Math.floor(diffMs / 3600000)
  const diffDays = Math.floor(diffMs / 86400000)

  if (diffMins < 1) return 'just now'
  if (diffMins < 60) return `${diffMins}m ago`
  if (diffHours < 24) return `${diffHours}h ago`
  return `${diffDays}d ago`
}

function formatDateTime(isoString) {
  return new Date(isoString).toLocaleString('en-US', {
    year: 'numeric', month: 'short', day: 'numeric',
    hour: '2-digit', minute: '2-digit', hour12: false,
  })
}

function InvestigationCard({ investigation, onClick }) {
  const {
    investigation_id,
    classification,
    severity,
    confidence,
    trigger_text,
    kill_chain_stages,
    created_at,
    analyst_rating,
    containment_priority,
  } = investigation

  const tier = CONFIDENCE_TIER(confidence)

  return (
    <div
      onClick={onClick}
      className="bg-sentinel-surface border border-sentinel-border 
                 rounded-xl p-5 hover:border-sentinel-accent 
                 transition-all cursor-pointer group"
    >
      <div className="flex items-start justify-between gap-4">
        {/* Left: icon + main info */}
        <div className="flex items-start gap-3 flex-1 min-w-0">
          <div className="mt-0.5 p-2 bg-sentinel-bg rounded-lg 
                          border border-sentinel-border flex-shrink-0">
            <Shield className="w-4 h-4 text-sentinel-accent" />
          </div>

          <div className="flex-1 min-w-0">
            {/* Badges row */}
            <div className="flex items-center gap-2 flex-wrap mb-2">
              {severity && (
                <span className={`text-xs font-bold px-2 py-0.5 rounded 
                                  uppercase tracking-wider 
                                  ${SEVERITY_STYLES[severity] || SEVERITY_STYLES.LOW}`}>
                  {severity}
                </span>
              )}
              {classification && (
                <span className={`text-xs font-mono px-2 py-0.5 rounded
                                  ${CLASSIFICATION_STYLES[classification] 
                                    || CLASSIFICATION_STYLES.UNKNOWN}`}>
                  {classification}
                </span>
              )}
              {containment_priority === 'IMMEDIATE' && (
                <span className="text-xs text-red-400 font-semibold">
                  ⚡ IMMEDIATE
                </span>
              )}
              {analyst_rating && (
                <span className="flex items-center gap-1 text-xs 
                                  text-sentinel-muted">
                  {RATING_ICON[analyst_rating]}
                  {analyst_rating}
                </span>
              )}
            </div>

            {/* Trigger text */}
            <p className="text-sm text-white font-medium leading-snug 
                           line-clamp-2 mb-2">
              {trigger_text || 'No trigger text available'}
            </p>

            {/* Meta row */}
            <div className="flex items-center gap-4 text-xs 
                             text-sentinel-muted flex-wrap">
              <span className="font-mono opacity-60">
                {investigation_id}
              </span>
              <span className="flex items-center gap-1">
                <Clock className="w-3 h-3" />
                {formatTimeAgo(created_at)}
              </span>
              {kill_chain_stages > 0 && (
                <span>
                  {kill_chain_stages} kill chain stages
                </span>
              )}
            </div>
          </div>
        </div>

        {/* Right: confidence + chevron */}
        <div className="flex items-center gap-3 flex-shrink-0">
          <div className="text-right">
            <div className="text-2xl font-bold text-sentinel-accent">
              {Math.round(confidence * 100)}%
            </div>
            <div className={`text-xs font-semibold ${tier.color}`}>
              {tier.label}
            </div>
          </div>
          <ChevronRight
            className="w-4 h-4 text-sentinel-muted 
                        group-hover:text-sentinel-accent transition-colors"
          />
        </div>
      </div>
    </div>
  )
}

export default function HistoryPage() {
  const navigate = useNavigate()
  const [investigations, setInvestigations] = useState([])
  const [total, setTotal] = useState(0)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [lastRefreshed, setLastRefreshed] = useState(null)

  const fetchHistory = async () => {
    setLoading(true)
    setError(null)
    try {
      const res = await fetch('/api/investigations/history')
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      const data = await res.json()
      const list = data.investigations || []
      setInvestigations(list)
      setTotal(data.total ?? list.length)
      setLastRefreshed(new Date())
    } catch (err) {
      setError('Failed to load investigation history. Is the backend running?')
      console.error('History fetch error:', err)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchHistory()
  }, [])

  const handleCardClick = (investigation) => {
    navigate(`/report/${investigation.investigation_id}`)
  }

  // Stats derived from loaded data
  const criticalCount = investigations.filter(
    i => i.severity === 'CRITICAL'
  ).length
  const aptCount = investigations.filter(
    i => i.classification === 'APT'
  ).length
  const feedbackCount = investigations.filter(
    i => i.analyst_rating
  ).length
  const avgConfidence = investigations.length > 0
    ? Math.round(
        investigations.reduce((sum, i) => sum + (i.confidence || 0), 0)
        / investigations.length * 100
      )
    : 0

  return (
    <div className="max-w-5xl mx-auto px-6 py-8">
      {/* Header */}
      <div className="flex items-center justify-between mb-8">
        <div>
          <h1 className="text-2xl font-bold text-white mb-1">
            Investigation History
          </h1>
          <p className="text-sm text-sentinel-muted flex items-center gap-2">
            <Database className="w-3.5 h-3.5" />
            Persistent storage via Supabase
            {lastRefreshed && (
              <span className="opacity-60">
                · Last refreshed {formatTimeAgo(lastRefreshed.toISOString())}
              </span>
            )}
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={fetchHistory}
            disabled={loading}
            className="flex items-center gap-2 px-3 py-2 
                       bg-sentinel-surface border border-sentinel-border 
                       hover:border-sentinel-accent rounded-lg text-sm 
                       transition-colors disabled:opacity-50"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </button>
          <div className="px-3 py-1.5 bg-sentinel-surface border 
                          border-sentinel-border rounded-lg text-sm 
                          text-sentinel-muted">
            {total} {total === 1 ? 'Record' : 'Records'}
          </div>
        </div>
      </div>

      {/* Stats bar */}
      {investigations.length > 0 && (
        <div className="grid grid-cols-4 gap-4 mb-6">
          {[
            { label: 'Total', value: total, color: 'text-sentinel-accent' },
            { label: 'Critical', value: criticalCount, color: 'text-red-400' },
            { label: 'APT', value: aptCount, color: 'text-orange-400' },
            { label: 'Avg Confidence', value: `${avgConfidence}%`, color: 'text-sentinel-accent' },
          ].map(stat => (
            <div
              key={stat.label}
              className="bg-sentinel-surface border border-sentinel-border 
                         rounded-xl p-4 text-center"
            >
              <div className={`text-2xl font-bold ${stat.color}`}>
                {stat.value}
              </div>
              <div className="text-xs text-sentinel-muted mt-1">
                {stat.label}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Loading state */}
      {loading && (
        <div className="flex items-center justify-center py-20">
          <div className="text-center">
            <div className="w-8 h-8 border-2 border-sentinel-accent 
                            border-t-transparent rounded-full animate-spin 
                            mx-auto mb-3" />
            <p className="text-sentinel-muted text-sm">
              Loading from Supabase...
            </p>
          </div>
        </div>
      )}

      {/* Error state */}
      {error && !loading && (
        <div className="bg-red-500/10 border border-red-500/30 
                        rounded-xl p-6 text-center">
          <XCircle className="w-8 h-8 text-red-400 mx-auto mb-3" />
          <p className="text-red-400 font-medium mb-1">
            Failed to load history
          </p>
          <p className="text-sm text-sentinel-muted mb-4">{error}</p>
          <button
            onClick={fetchHistory}
            className="px-4 py-2 bg-sentinel-surface border 
                       border-sentinel-border rounded-lg text-sm 
                       hover:border-sentinel-accent transition-colors"
          >
            Try again
          </button>
        </div>
      )}

      {/* Empty state */}
      {!loading && !error && investigations.length === 0 && (
        <div className="text-center py-20">
          <Clock className="w-12 h-12 text-sentinel-muted mx-auto mb-4 
                             opacity-40" />
          <p className="text-sentinel-muted font-medium mb-1">
            No investigations yet
          </p>
          <p className="text-sm text-sentinel-muted opacity-60">
            Run an investigation to see it here
          </p>
        </div>
      )}

      {/* Investigation cards */}
      {!loading && !error && investigations.length > 0 && (
        <div className="space-y-3">
          {investigations.map((investigation) => (
            <InvestigationCard
              key={investigation.investigation_id}
              investigation={investigation}
              onClick={() => handleCardClick(investigation)}
            />
          ))}
        </div>
      )}

      {/* Supabase note */}
      {!loading && !error && (
        <p className="text-center text-xs text-sentinel-muted 
                       opacity-40 mt-8">
          Investigation history persisted to Supabase PostgreSQL.
          Data survives session reloads.
        </p>
      )}
    </div>
  )
}
