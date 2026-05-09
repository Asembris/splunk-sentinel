import { useParams, useNavigate } from 'react-router-dom'
import { useState, useEffect } from 'react'
import { useInvestigation } from '../store/InvestigationContext'
import { 
  Download, ArrowLeft, FileJson, Printer, 
  Share2, Loader2, AlertCircle, FileText 
} from 'lucide-react'
import ExecutiveSummary from '../components/report/ExecutiveSummary'
import FindingsGrid from '../components/report/FindingsGrid'
import MitreTable from '../components/report/MitreTable'
import ThreatIntelCards from '../components/report/ThreatIntelCards'
import RecommendedActions from '../components/report/RecommendedActions'
import CveList from '../components/report/CveList'

function FeedbackCard({
  feedbackRating,
  setFeedbackRating,
  feedbackNotes,
  setFeedbackNotes,
  feedbackStatus,
  onSubmit,
}) {
  const RATINGS = [
    {
      key: 'correct',
      label: 'Correct',
      icon: '✓',
      activeClass: 'border-green-500 bg-green-500/10 text-green-400',
      inactiveClass: 'border-sentinel-border text-sentinel-muted hover:border-green-500/50',
    },
    {
      key: 'partial',
      label: 'Partial',
      icon: '~',
      activeClass: 'border-amber-500 bg-amber-500/10 text-amber-400',
      inactiveClass: 'border-sentinel-border text-sentinel-muted hover:border-amber-500/50',
    },
    {
      key: 'incorrect',
      label: 'Incorrect',
      icon: '✗',
      activeClass: 'border-red-500 bg-red-500/10 text-red-400',
      inactiveClass: 'border-sentinel-border text-sentinel-muted hover:border-red-500/50',
    },
  ]

  if (feedbackStatus === 'submitted') {
    return (
      <div className="bg-sentinel-surface border border-green-500/30 
                      rounded-xl p-6 mt-6">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 bg-green-500/20 rounded-full 
                          flex items-center justify-center flex-shrink-0">
            <span className="text-green-400 font-bold">✓</span>
          </div>
          <div>
            <p className="text-sm font-semibold text-green-400">
              Feedback submitted
            </p>
            <p className="text-xs text-sentinel-muted mt-0.5">
              Thank you. This investigation has been rated and 
              saved to the evaluation dataset.
            </p>
          </div>
        </div>
      </div>
    )
  }

  return (
    <div className="bg-sentinel-surface border border-sentinel-border 
                    rounded-xl p-6 mt-6">
      {/* Header */}
      <div className="flex items-center gap-2 mb-4">
        <div className="w-1.5 h-4 bg-sentinel-accent rounded-full" />
        <h3 className="text-sm font-semibold text-sentinel-muted 
                       uppercase tracking-wider">
          Analyst Feedback
        </h3>
        <span className="text-xs text-sentinel-muted opacity-50 ml-1">
          — contributes to evaluation dataset
        </span>
      </div>

      <p className="text-xs text-sentinel-muted mb-4">
        Was this autonomous investigation accurate? Your rating 
        is stored in Supabase and used to calibrate future 
        confidence scores.
      </p>

      {/* Rating buttons */}
      <div className="flex items-center gap-3 mb-4">
        {RATINGS.map((rating) => (
          <button
            key={rating.key}
            onClick={() => setFeedbackRating(rating.key)}
            disabled={feedbackStatus === 'submitting'}
            className={`flex items-center gap-2 px-4 py-2 rounded-lg 
                        border text-sm font-medium transition-all
                        disabled:opacity-50 disabled:cursor-not-allowed
                        ${feedbackRating === rating.key
                          ? rating.activeClass
                          : rating.inactiveClass
                        }`}
          >
            <span className="font-bold">{rating.icon}</span>
            {rating.label}
          </button>
        ))}
      </div>

      {/* Notes input — only shown when rating selected */}
      {feedbackRating && (
        <div className="mb-4">
          <textarea
            value={feedbackNotes}
            onChange={(e) => setFeedbackNotes(e.target.value)}
            placeholder="Optional: describe what was correct or incorrect (e.g. 'Patient zero IP was wrong — actual source was 54.67.127.227')"
            disabled={feedbackStatus === 'submitting'}
            rows={3}
            className="w-full bg-sentinel-bg border border-sentinel-border 
                       rounded-lg px-3 py-2 text-sm text-white 
                       placeholder:text-sentinel-muted/50
                       focus:outline-none focus:border-sentinel-accent
                       resize-none disabled:opacity-50
                       transition-colors"
          />
          <p className="text-xs text-sentinel-muted mt-1 opacity-60">
            Your notes help build the ground truth evaluation dataset
          </p>
        </div>
      )}

      {/* Submit button */}
      <div className="flex items-center justify-between">
        <div>
          {feedbackStatus === 'error' && (
            <p className="text-xs text-red-400">
              Failed to submit feedback. Please try again.
            </p>
          )}
        </div>
        <button
          onClick={onSubmit}
          disabled={!feedbackRating || feedbackStatus === 'submitting'}
          className={`flex items-center gap-2 px-4 py-2 rounded-lg 
                      text-sm font-medium transition-all
                      ${!feedbackRating || feedbackStatus === 'submitting'
                        ? 'bg-sentinel-surface border border-sentinel-border opacity-40 cursor-not-allowed'
                        : 'bg-sentinel-accent hover:bg-blue-500 text-white cursor-pointer'
                      }`}
        >
          {feedbackStatus === 'submitting' ? (
            <>
              <div className="w-4 h-4 border-2 border-white/30 
                              border-t-white rounded-full animate-spin" />
              Submitting...
            </>
          ) : (
            <>
              Submit Feedback
            </>
          )}
        </button>
      </div>
    </div>
  )
}

function AuditChainBadge({ auditChain, expanded, onToggle, splAuditLog }) {
  if (!auditChain) {
    return (
      <div className="flex items-center gap-1.5 px-3 py-1.5 
                      bg-sentinel-surface border border-sentinel-border 
                      rounded-lg text-xs text-sentinel-muted">
        <div className="w-3 h-3 border border-sentinel-muted 
                        border-t-transparent rounded-full animate-spin" />
        Verifying audit chain...
      </div>
    )
  }

  if (auditChain.error) {
    return (
      <div className="flex items-center gap-1.5 px-3 py-1.5
                      bg-sentinel-surface border border-sentinel-border
                      rounded-lg text-xs text-sentinel-muted">
        ◌ Audit verification unavailable
      </div>
    )
  }

  const isValid = auditChain.valid === true

  let totalEntries = auditChain.total_entries || 0
  if (!totalEntries && auditChain.details) {
    const match = auditChain.details.match(/verified (\d+) entries/i)
    if (match) {
      totalEntries = parseInt(match[1], 10)
    } else if (auditChain.details.includes('empty')) {
      totalEntries = 0
    } else if (splAuditLog && Array.isArray(splAuditLog)) {
      totalEntries = splAuditLog.length
    }
  }

  let brokenIndex = auditChain.first_broken_index
  if (brokenIndex === undefined && auditChain.details && !isValid) {
    const match = auditChain.details.match(/Entry (\d+)/i)
    if (match) brokenIndex = match[1]
  }

  // Parse last 5 entries from spl_audit_log if available
  const recentEntries = []
  if (splAuditLog && Array.isArray(splAuditLog)) {
    const last5 = splAuditLog.slice(-5)
    for (const entry of last5) {
      try {
        const parsed = typeof entry === 'string'
          ? JSON.parse(entry)
          : entry
        recentEntries.push(parsed)
      } catch {
        // skip unparseable entries
      }
    }
  }

  return (
    <div className="relative" data-audit-badge>
      <button
        onClick={onToggle}
        className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg
                    text-xs font-medium transition-all border
                    ${isValid
                      ? 'bg-green-500/10 border-green-500/30 text-green-400 hover:bg-green-500/20'
                      : 'bg-red-500/10 border-red-500/30 text-red-400 hover:bg-red-500/20'
                    }`}
      >
        <span>{isValid ? '🔒' : '⚠️'}</span>
        <span>
          {isValid
            ? `Audit Chain Verified · ${totalEntries} entries`
            : `Chain Integrity Failure · Entry ${brokenIndex} modified`
          }
        </span>
        <span className={`transition-transform ${expanded ? 'rotate-180' : ''}`}>
          ▾
        </span>
      </button>

      {/* Expanded dropdown */}
      {expanded && (
        <div className="absolute right-0 top-full mt-2 z-50
                        bg-sentinel-surface border border-sentinel-border
                        rounded-xl shadow-2xl p-4 w-96">

          {/* Chain summary */}
          <div className="flex items-center justify-between mb-3">
            <span className="text-xs font-semibold text-sentinel-muted uppercase tracking-wider">
              Hash Chain Integrity
            </span>
            <span className={`text-xs font-bold ${
              isValid ? 'text-green-400' : 'text-red-400'
            }`}>
              {isValid ? '✓ INTACT' : '✗ BROKEN'}
            </span>
          </div>

          {/* Stats row */}
          <div className="grid grid-cols-3 gap-2 mb-3">
            {[
              { label: 'Entries', value: totalEntries },
              { label: 'Status', value: isValid ? 'Valid' : 'Invalid' },
              { label: 'Algorithm', value: 'SHA-256' },
            ].map(stat => (
              <div key={stat.label}
                   className="bg-sentinel-bg rounded-lg p-2 text-center">
                <div className="text-xs font-bold text-white">
                  {stat.value}
                </div>
                <div className="text-xs text-sentinel-muted">
                  {stat.label}
                </div>
              </div>
            ))}
          </div>

          {/* Details */}
          <p className="text-xs text-sentinel-muted mb-3 leading-relaxed break-all">
            {auditChain.details}
          </p>

          {/* Recent entries */}
          {recentEntries.length > 0 && (
            <>
              <div className="text-xs font-semibold text-sentinel-muted 
                              uppercase tracking-wider mb-2">
                Recent SPL Entries
              </div>
              <div className="space-y-1.5 max-h-48 overflow-y-auto">
                {recentEntries.map((entry, i) => (
                  <div key={i}
                       className="bg-sentinel-bg rounded-lg p-2 font-mono">
                    <div className="flex items-center justify-between mb-1">
                      <span className={`text-xs font-bold ${
                        entry.was_corrected
                          ? 'text-amber-400'
                          : 'text-green-400'
                      }`}>
                        {entry.was_corrected ? '⟳ corrected' : '✓ clean'}
                      </span>
                      <span className="text-xs text-sentinel-muted">
                        {entry.rows_returned ?? '?'} rows
                      </span>
                    </div>
                    <div className="text-xs text-sentinel-muted truncate">
                      {entry.spl?.slice(0, 60)}...
                    </div>
                    {entry.entry_hash && (
                      <div className="text-xs text-sentinel-muted/40 mt-1">
                        #{entry.entry_hash.slice(0, 16)}...
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </>
          )}

          {/* Verification timestamp */}
          <p className="text-xs text-sentinel-muted/40 mt-3 text-right">
            Verified {auditChain.verified_at
              ? new Date(auditChain.verified_at).toLocaleTimeString()
              : 'just now'}
          </p>
        </div>
      )}
    </div>
  )
}

export default function ReportPage() {
  const { id } = useParams()
  const { state } = useInvestigation()
  const navigate = useNavigate()
  
  const [historicalData, setHistoricalData] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const [pdfLoading, setPdfLoading] = useState(false)
  const [pdfError, setPdfError] = useState(null)
  
  const [feedbackRating, setFeedbackRating] = useState(null)
  const [feedbackNotes, setFeedbackNotes] = useState('')
  const [feedbackStatus, setFeedbackStatus] = useState('idle')
  // idle | submitting | submitted | error

  const [auditChain, setAuditChain] = useState(null)
  // null = loading, object = result
  const [auditExpanded, setAuditExpanded] = useState(false)

  // Use state.result if available, otherwise use historicalData
  const activeResult = state.result || historicalData
  const report = activeResult?.final_report

  useEffect(() => {
    // If we have an ID in the URL and no live state, fetch from backend
    if (id && !state.result) {
      const fetchHistoricalReport = async () => {
        setLoading(true)
        setError(null)
        try {
          const res = await fetch(`/api/investigations/${id}`)
          if (!res.ok) {
            if (res.status === 404) throw new Error('Investigation not found')
            throw new Error('Failed to fetch historical report')
          }
          const data = await res.json()
          setHistoricalData(data)
        } catch (err) {
          console.error('Report fetch error:', err)
          setError(err.message)
        } finally {
          setLoading(false)
        }
      }
      fetchHistoricalReport()
    }
  }, [id, state.result])

  useEffect(() => {
    const verifyChain = async () => {
      try {
        const investigationId =
          report?.investigation_id ||
          state.result?.investigation_id

        if (!investigationId) return

        // Try investigation-specific endpoint first
        // Fall back to verify-latest
        const url = investigationId
          ? `/api/audit-log/verify/${investigationId}`
          : `/api/audit-log/verify-latest`

        const res = await fetch(url)
        if (!res.ok) throw new Error(`HTTP ${res.status}`)
        const data = await res.json()
        setAuditChain(data)
      } catch (err) {
        console.error('Audit chain verification failed:', err)
        setAuditChain({ valid: false, error: err.message })
      }
    }

    verifyChain()
  }, [report?.investigation_id, state.result?.investigation_id])

  useEffect(() => {
    if (!auditExpanded) return
    const handleClick = (e) => {
      if (!e.target.closest('[data-audit-badge]')) {
        setAuditExpanded(false)
      }
    }
    document.addEventListener('mousedown', handleClick)
    return () => document.removeEventListener('mousedown', handleClick)
  }, [auditExpanded])

  const handleExportJson = () => {
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(activeResult, null, 2));
    const downloadAnchorNode = document.createElement('a');
    downloadAnchorNode.setAttribute("href",     dataStr);
    downloadAnchorNode.setAttribute("download", `sentinel-report-${id || state.investigationId}.json`);
    document.body.appendChild(downloadAnchorNode);
    downloadAnchorNode.click();
    downloadAnchorNode.remove();
  }

  const handleDownloadPdf = async () => {
    const investigationId =
      activeResult?.investigation_id ||
      id ||
      state.investigationId

    if (!investigationId) {
      console.error('No investigation ID available for PDF download')
      return
    }

    const startTime = Date.now()
    try {
      setPdfLoading(true)
      const response = await fetch(
        `/api/investigations/${investigationId}/report/pdf`
      )

      if (!response.ok) {
        if (response.status === 404) {
          throw new Error(
            'PDF not found. The report may still be generating.'
          )
        }
        throw new Error(`Download failed: HTTP ${response.status}`)
      }

      // Create blob and trigger download
      const blob = await response.blob()
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `splunk-sentinel-${investigationId}.pdf`
      document.body.appendChild(a)
      a.click()
      document.body.removeChild(a)
      URL.revokeObjectURL(url)

    } catch (err) {
      console.error('PDF download error:', err)
      setPdfError(err.message)
      // Clear error after 4 seconds
      setTimeout(() => setPdfError(null), 4000)
    } finally {
      // Ensure the loading state is visible for at least 800ms
      const duration = Date.now() - startTime
      const delay = Math.max(0, 800 - duration)
      
      setTimeout(() => {
        setPdfLoading(false)
      }, delay)
    }
  }

  const handleSubmitFeedback = async () => {
    if (!feedbackRating) return

    const investigationId =
      activeResult?.investigation_id ||
      id ||
      state.investigationId

    if (!investigationId) return

    const startTime = Date.now()
    setFeedbackStatus('submitting')

    try {
      const response = await fetch(
        `/api/investigations/${investigationId}/feedback`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            rating: feedbackRating,
            notes: feedbackNotes,
          }),
        }
      )

      if (!response.ok) throw new Error(`HTTP ${response.status}`)
      const data = await response.json()

      // Artificial delay to ensure spinner is visible for UX
      const duration = Date.now() - startTime
      const minDelay = 1000
      if (duration < minDelay) {
        await new Promise((resolve) => setTimeout(resolve, minDelay - duration))
      }

      if (data.status === 'ok' || data.status === 'saved') {
        setFeedbackStatus('submitted')
      } else {
        throw new Error('Feedback save failed')
      }
    } catch (err) {
      console.error('Feedback error:', err)
      setFeedbackStatus('error')
      setTimeout(() => setFeedbackStatus('idle'), 3000)
    }
  }

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center h-[calc(100vh-57px)]">
        <Loader2 className="w-10 h-10 text-sentinel-accent animate-spin mb-4" />
        <p className="text-sentinel-muted animate-pulse">Retrieving historical report...</p>
      </div>
    )
  }

  if (error) {
    return (
      <div className="flex flex-col items-center justify-center h-[calc(100vh-57px)]">
        <div className="bg-red-500/10 border border-red-500/20 p-8 rounded-2xl text-center max-w-md">
          <AlertCircle className="w-12 h-12 text-red-400 mx-auto mb-4" />
          <h2 className="text-xl font-bold text-white mb-2">Report Error</h2>
          <p className="text-sentinel-muted mb-6">{error}</p>
          <button
            onClick={() => navigate('/history')}
            className="px-6 py-2 bg-sentinel-surface border border-sentinel-border hover:border-red-500/50 text-white rounded-lg transition-all"
          >
            Return to History
          </button>
        </div>
      </div>
    )
  }

  if (!report) {
    return (
      <div className="flex items-center justify-center h-[calc(100vh-57px)]">
        <div className="text-center animate-fade-in">
          <p className="text-sentinel-muted mb-4">No report available in current session</p>
          <button
            onClick={() => navigate('/')}
            className="px-6 py-2 bg-sentinel-accent text-white rounded-lg text-sm font-medium hover:bg-blue-500 transition-colors"
          >
            Start Investigation
          </button>
        </div>
      </div>
    )
  }

  const severityColors = {
    CRITICAL: 'bg-red-900/30 text-sentinel-danger border-sentinel-danger',
    HIGH: 'bg-orange-900/30 text-orange-400 border-orange-400',
    MEDIUM: 'bg-yellow-900/30 text-sentinel-warning border-sentinel-warning',
    LOW: 'bg-green-900/30 text-sentinel-success border-sentinel-success',
  }

  return (
    <div className="max-w-5xl mx-auto px-6 py-8 animate-fade-in">
      {/* Report header */}
      <div className="flex items-start justify-between mb-8">
        <div>
          <button
            onClick={() => navigate('/dashboard')}
            className="flex items-center gap-2 text-sm text-sentinel-muted hover:text-white mb-4 transition-colors group"
          >
            <ArrowLeft className="w-4 h-4 group-hover:-translate-x-1 transition-transform" /> Back to Dashboard
          </button>
          <div className="flex items-center gap-3 mb-2">
            <span className={`text-[10px] font-bold px-2.5 py-0.5 rounded-full border uppercase tracking-wider ${
              severityColors[report.severity] || severityColors.HIGH
            }`}>
              {report.severity}
            </span>
            <span className="text-[10px] font-mono text-sentinel-accent bg-blue-900/20 border border-blue-900 px-2.5 py-0.5 rounded-full uppercase tracking-wider">
              {report.classification}
            </span>
            
            <AuditChainBadge
              auditChain={auditChain}
              expanded={auditExpanded}
              onToggle={() => setAuditExpanded(prev => !prev)}
              splAuditLog={activeResult?.spl_audit_log || []}
            />
          </div>
          <h1 className="text-3xl font-bold text-white tracking-tight">Automated Investigation Report</h1>
          <p className="text-xs text-sentinel-muted font-mono mt-1 flex items-center gap-2">
            <span className="bg-sentinel-border px-1.5 py-0.5 rounded text-gray-400">{report.investigation_id || state.investigationId}</span>
            <span>·</span>
            <span>{report.generated_at ? new Date(report.generated_at).toLocaleString() : 'Just now'}</span>
          </p>
        </div>
        <div className="flex items-center gap-4">
          <div className="text-right mr-4 border-r border-sentinel-border pr-6">
            <div className="text-3xl font-bold text-sentinel-accent leading-none">
              {Math.round((report.investigation_confidence || 0) * 100)}%
            </div>
            <div className="text-[10px] text-sentinel-muted uppercase tracking-widest mt-1">confidence</div>
          </div>
          <div className="flex gap-2">
            <button
              onClick={handleExportJson}
              className="p-2.5 bg-sentinel-surface border border-sentinel-border hover:border-sentinel-accent text-white rounded-xl transition-all shadow-lg active:scale-95 group"
              title="Download JSON"
            >
              <FileJson className="w-5 h-5 text-sentinel-accent group-hover:scale-110 transition-transform" />
            </button>
            <div className="flex flex-col items-end gap-1">
              <button
                onClick={handleDownloadPdf}
                disabled={pdfLoading}
                className={`flex items-center gap-2 px-4 py-2 rounded-lg 
                            text-sm font-medium transition-all
                            ${pdfLoading
                              ? 'bg-sentinel-surface border border-sentinel-border opacity-70 cursor-wait'
                              : 'bg-sentinel-accent hover:bg-blue-500 text-white cursor-pointer'
                            }`}
              >
                {pdfLoading ? (
                  <>
                    <div className="w-4 h-4 border-2 border-white/30 
                                    border-t-white rounded-full animate-spin" />
                    Downloading...
                  </>
                ) : (
                  <>
                    <FileText className="w-4 h-4" />
                    Download PDF
                  </>
                )}
              </button>
              {pdfError && (
                <p className="text-xs text-red-400 max-w-48 text-right">
                  {pdfError}
                </p>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* Report sections */}
      <div className="space-y-6">
        <ExecutiveSummary report={report} />
        <FindingsGrid findings={report.key_findings || []} />
        <RecommendedActions actions={report.recommended_actions || []} />
        <MitreTable
          techniques={report.mitre_techniques_used || []}
          ttpMappings={activeResult?.ttp_mappings || []}
        />
        <ThreatIntelCards threatIntel={activeResult?.threat_intel || {}} />
        <CveList cves={report.cves_identified || []} />
        
        {/* Analyst Feedback */}
        <FeedbackCard
          feedbackRating={feedbackRating}
          setFeedbackRating={setFeedbackRating}
          feedbackNotes={feedbackNotes}
          setFeedbackNotes={setFeedbackNotes}
          feedbackStatus={feedbackStatus}
          onSubmit={handleSubmitFeedback}
        />
        
        <div className="pt-8 text-center border-t border-sentinel-border opacity-30">
          <p className="text-[10px] text-sentinel-muted uppercase tracking-[0.2em]">
            End of Automated Incident Report — Splunk Sentinel
          </p>
        </div>
      </div>
    </div>
  )
}
