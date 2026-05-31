import { useParams, useNavigate } from 'react-router-dom'
import { Component, useState, useEffect, useRef, useCallback } from 'react'
import { useInvestigation } from '../store/InvestigationContext'
import { 
  Download, ArrowLeft, FileJson, Printer, 
  Share2, Loader2, AlertCircle, FileText,
  Zap, Shield, Play, RotateCcw, CheckCircle2, Circle, Clock,
  Send, Sparkles
} from 'lucide-react'
import ExecutiveSummary from '../components/report/ExecutiveSummary'
import FindingsGrid from '../components/report/FindingsGrid'
import MitreTable from '../components/report/MitreTable'
import ThreatIntelCards from '../components/report/ThreatIntelCards'
import RecommendedActions from '../components/report/RecommendedActions'
import CveList from '../components/report/CveList'
import KillChainTimeline from '../components/report/KillChainTimeline'

const asArray = (value) => (Array.isArray(value) ? value : [])

const REPORT_SEVERITY_TONES = {
  CRITICAL: 'bg-red-900/30 text-sentinel-danger border-sentinel-danger',
  HIGH: 'bg-orange-900/30 text-orange-400 border-orange-400',
  MEDIUM: 'bg-yellow-900/30 text-sentinel-warning border-sentinel-warning',
  LOW: 'bg-green-900/30 text-sentinel-success border-sentinel-success',
}

const REPORT_CLASSIFICATION_TONES = {
  APT: 'text-sentinel-accent bg-blue-900/20 border-blue-900',
  RANSOMWARE: 'text-sentinel-accent bg-blue-900/20 border-blue-900',
  INSIDER_THREAT: 'text-sentinel-accent bg-blue-900/20 border-blue-900',
  UNKNOWN: 'text-sentinel-muted bg-sentinel-bg border-sentinel-border',
}

const REPORT_CONFIDENCE_TONES = {
  high: {
    text: 'text-green-400',
    bar: 'bg-green-400',
    chip: 'bg-green-500/10 text-green-400 border-green-500/30',
  },
  medium: {
    text: 'text-amber-400',
    bar: 'bg-amber-400',
    chip: 'bg-amber-500/10 text-amber-400 border-amber-500/30',
  },
  low: {
    text: 'text-red-400',
    bar: 'bg-red-400',
    chip: 'bg-red-500/10 text-red-400 border-red-500/30',
  },
}

const REPORT_SLO_TONES = {
  PASS: {
    chip: 'bg-green-500/5 border-green-500/20 text-green-400/80 hover:border-green-500/40',
    icon: 'text-green-400',
  },
  BREACH: {
    chip: 'bg-red-500/5 border-red-500/20 text-red-400/80 hover:border-red-500/40',
    icon: 'text-red-400',
  },
}

const normalizeReportToken = (value) => (
  String(value || '')
    .trim()
    .toUpperCase()
    .replace(/[\s-]+/g, '_')
)

const getReportConfidenceTone = (confidencePct) => {
  if (confidencePct >= 75) return REPORT_CONFIDENCE_TONES.high
  if (confidencePct >= 50) return REPORT_CONFIDENCE_TONES.medium
  return REPORT_CONFIDENCE_TONES.low
}

const normalizeContainmentPlan = (plan) => {
  if (!plan || typeof plan !== 'object') {
    return { phases: [], chat_history: [] }
  }

  return {
    ...plan,
    phases: asArray(plan.phases).map((phase) => ({
      ...phase,
      actions: asArray(phase?.actions),
    })),
    chat_history: asArray(plan.chat_history),
  }
}

class RouteSectionErrorBoundary extends Component {
  constructor(props) {
    super(props)
    this.state = { hasError: false }
  }

  static getDerivedStateFromError() {
    return { hasError: true }
  }

  componentDidCatch(error) {
    console.error(
      `[ReportPage] Section crash: ${this.props.sectionName || 'unknown'}`,
      error
    )
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="bg-sentinel-surface border border-sentinel-border rounded-xl p-4">
          <p className="text-xs text-sentinel-muted">
            This section is temporarily unavailable for this investigation.
          </p>
        </div>
      )
    }
    return this.props.children
  }
}


function ContainmentPlanPanel({ investigationId, plan, onUpdate }) {
  const [executingPhase, setExecutingPhase] = useState(null)
  const [executing, setExecuting] = useState(false)
  const [progress, setProgress] = useState({}) // { actionId: 'pending' | 'running' | 'success' | 'error' }
  const [localPlan, setLocalPlan] = useState(plan)

  // Chat states
  const [chatMessages, setChatMessages] = useState([])
  const [inputValue, setInputValue] = useState('')
  const [isStreaming, setIsStreaming] = useState(false)
  const messagesEndRef = useRef(null)
  const chatContainerRef = useRef(null)

  // Sync local plan with props if props change
  useEffect(() => {
    setLocalPlan(normalizeContainmentPlan(plan))
  }, [plan])

  const fetchContainmentPlan = async () => {
    try {
      const res = await fetch(
        `/api/investigations/${investigationId}/containment-plan`
      )
      if (!res.ok) return
      const refreshed = await res.json()
      const normalized = normalizeContainmentPlan(refreshed)
      setLocalPlan(normalized)
      onUpdate(normalized)
    } catch (err) {
      console.error('Failed to refresh containment plan:', err)
    }
  }

  // Scroll to bottom of chat container only (not the whole page)
  useEffect(() => {
    if (chatContainerRef.current) {
      chatContainerRef.current.scrollTop = chatContainerRef.current.scrollHeight
    }
  }, [chatMessages])

  // Fetch initial message and chat history on mount
  useEffect(() => {
    const fetchChatInit = async () => {
      try {
        const res = await fetch(`/api/investigations/${investigationId}/containment-plan/chat/init`)
        if (res.ok) {
          const history = await res.json()
          setChatMessages(history)
        }
      } catch (err) {
        console.error('Failed to initialize containment chat:', err)
      }
    }
    if (investigationId) {
      fetchChatInit()
    }
  }, [investigationId])

  // Authoritative reconciliation polling while execution is active
  useEffect(() => {
    if (!executing || !investigationId) return

    const interval = setInterval(async () => {
      try {
        const res = await fetch(
          `/api/investigations/${investigationId}/containment-plan`
        )
        if (!res.ok) return
        const data = normalizeContainmentPlan(await res.json())

        // Always reconcile from backend while a phase is executing.
        setLocalPlan(data)
        onUpdate(data)

        if (executingPhase === null) {
          setExecuting(false)
          clearInterval(interval)
          return
        }

        const currentPhase = asArray(data.phases)[executingPhase]
        if (!currentPhase) {
          setExecuting(false)
          setExecutingPhase(null)
          clearInterval(interval)
          return
        }

        const unresolvedStatuses = new Set([
          'PENDING',
          'EXECUTING',
          'VERIFYING',
        ])
        const hasUnresolved = asArray(currentPhase.actions).some(action =>
          unresolvedStatuses.has(action.status || 'PENDING')
        )

        if (!hasUnresolved) {
          setExecuting(false)
          setExecutingPhase(null)
          clearInterval(interval)
        }
      } catch (err) {
        // Network errors are transient here; keep polling.
      }
    }, 3000)

    return () => clearInterval(interval)
  }, [executing, investigationId, executingPhase])

  const getValidationWarning = (text) => {
    const val = text.toLowerCase().trim()
    if (!val) return null
    
    if (val.includes('127.0.0.1') || val.includes('192.168.1.')) {
      return "Protected IP Subnet warning: 192.168.1.0/24 and localhost are excluded by policy."
    }
    
    const hosts = ['active-directory-controller', 'domain-controller', 'ad-server', 'auth-server', 'identity-server']
    if (hosts.some(h => val.includes(h))) {
      return "Protected Host warning: critical identity and AD infrastructure cannot be isolated."
    }
    
    const users = ['administrator', 'domain-admin', 'root', 'system', 'sa']
    if (users.some(u => val.includes(u))) {
      return "Protected User warning: administrative and system identities cannot be modified."
    }
    
    return null
  }

  const validationWarning = getValidationWarning(inputValue)

  const handleTargetChange = (phaseIdx, actionIdx, newTarget) => {
    const updatedPlan = { ...localPlan }
    updatedPlan.phases[phaseIdx].actions[actionIdx].target = newTarget
    setLocalPlan(updatedPlan)
  }

  const saveChanges = async () => {
    try {
      const res = await fetch(`/api/investigations/${investigationId}/containment-plan`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(localPlan)
      })
      if (res.ok) onUpdate(localPlan)
    } catch (err) {
      console.error('Failed to save containment plan:', err)
    }
  }

  const executePhase = async (phaseIdx) => {
    setExecutingPhase(phaseIdx)
    setExecuting(true)
    setLocalPlan(prev => {
      if (!prev) return prev
      return {
        ...prev,
        phases: asArray(prev.phases).map((phase, idx) => {
          if (idx !== phaseIdx) return phase
          return {
            ...phase,
            actions: asArray(phase.actions).map(action => ({
              ...action,
              status: action.status === 'PENDING' ? 'EXECUTING' : action.status,
            })),
          }
        }),
      }
    })

    const updateActionStatus = (actionId, newStatus) => {
      setLocalPlan(prev => {
        if (!prev) return prev
        return {
          ...prev,
          phases: asArray(prev.phases).map(phase => ({
            ...phase,
            actions: asArray(phase.actions).map(action =>
              (action.action_id === actionId ||
               action.id === actionId)
                ? { ...action, status: newStatus }
                : action
            )
          }))
        }
      })
    }

    try {
      const response = await fetch(
        `/api/investigations/${investigationId}/containment-plan/execute?phase_idx=${phaseIdx}`,
        { headers: { Accept: 'text/event-stream' } }
      )
      if (!response.ok || !response.body) {
        throw new Error(`HTTP ${response.status}`)
      }

      const reader = response.body.getReader()
      const decoder = new TextDecoder()
      let buffer = ''

      while (true) {
        const { value, done } = await reader.read()
        if (done) break

        buffer += decoder.decode(value, { stream: true })
        const events = buffer.split(/\r?\n\r?\n/)
        buffer = events.pop() || ''

        for (const eventText of events) {
          const dataLine = eventText
            .split(/\r?\n/)
            .find(line => line.trim().startsWith('data:'))
          if (!dataLine) continue

          const data = JSON.parse(dataLine.slice(dataLine.indexOf(':') + 1).trim())
          console.debug('[CONTAINMENT SSE]', data)

          if (data.event === 'action_started') {
            setProgress(prev => ({ ...prev, [data.action_id]: 'running' }))
            updateActionStatus(data.action_id, 'EXECUTING')
          } else if (data.event === 'action_complete') {
            setProgress(prev => ({ ...prev, [data.action_id]: 'success' }))
            updateActionStatus(data.action_id, 'VERIFYING')
          } else if (data.event === 'action_failed') {
            setProgress(prev => ({ ...prev, [data.action_id]: 'error' }))
            updateActionStatus(data.action_id, 'FAILED')
          } else if (data.event === 'phase_complete') {
            const normalizedPlan = normalizeContainmentPlan(data.plan)
            setLocalPlan(normalizedPlan)
            onUpdate(normalizedPlan)
            // Keep executing/polling active until async verification settles.
          }
        }
      }
    } catch (err) {
      console.error('SSE Error:', err)
    } finally {
      // Do not clear phase tracking here; reconciliation polling decides
      // when the phase has fully settled (post-verification).
    }
  }

  const canRollback = (action) => {
    const rollbackEligibleStatuses = new Set([
      'EXECUTED',
      'VERIFYING',
      'VERIFIED_EFFECTIVE',
      'PARTIAL_EFFECT',
      'VERIFICATION_FAILED',
      'ROLLBACK_RECOMMENDED',
      'VERIFICATION_SKIPPED',
    ])
    return (
      rollbackEligibleStatuses.has(action.status) &&
      action.reversal_spl &&
      !action.rolled_back_at
    )
  }

  const handleRollback = async (actionId) => {
    try {
      const res = await fetch(`/api/investigations/${investigationId}/containment-plan/rollback?action_id=${actionId}`, {
        method: 'POST'
      })
      if (res.ok) {
        await fetchContainmentPlan()
      }
    } catch (err) {
      console.error('Rollback failed:', err)
    }
  }

  const getStatusBadge = (action) => {
    const status = action.status || 'PENDING'
    const verResult = action.verification_result

    const badges = {
      'PENDING': {
        color: 'text-sentinel-muted border-sentinel-border',
        label: 'PENDING',
        icon: 'o'
      },
      'EXECUTING': {
        color: 'text-blue-400 border-blue-500/30',
        label: 'EXECUTING',
        icon: '~'
      },
      'VERIFYING': {
        color: 'text-blue-400 border-blue-500/30',
        label: 'VERIFYING...',
        icon: '...'
      },
      'VERIFIED_EFFECTIVE': {
        color: 'text-green-400 border-green-500/30',
        label: 'VERIFIED',
        icon: '*'
      },
      'PARTIAL_EFFECT': {
        color: 'text-amber-400 border-amber-500/30',
        label: 'PARTIAL EFFECT',
        icon: '~'
      },
      'VERIFICATION_FAILED': {
        color: 'text-red-400 border-red-500/30',
        label: 'VERIFY FAILED',
        icon: 'x'
      },
      'ROLLBACK_RECOMMENDED': {
        color: 'text-red-400 border-red-500/30',
        label: 'ROLLBACK RECOMMENDED',
        icon: '!'
      },
      'VERIFICATION_SKIPPED': {
        color: 'text-sentinel-muted border-sentinel-border',
        label: 'EXECUTED',
        icon: '*'
      },
      'EXECUTED': {
        color: 'text-green-400 border-green-500/30',
        label: 'EXECUTED',
        icon: '*'
      },
      'ROLLED_BACK': {
        color: 'text-sentinel-muted border-sentinel-border',
        label: 'ROLLED BACK',
        icon: '<-'
      },
      'FAILED': {
        color: 'text-red-400 border-red-500/30',
        label: 'FAILED',
        icon: 'x'
      },
    }

    const badge = badges[status] || badges.PENDING

    return (
      <div>
        <span className={`text-xs px-2 py-1 rounded border font-medium ${badge.color}`}>
          {badge.icon} {badge.label}
        </span>

        {verResult && verResult.before_count !== undefined && (
          <div className="text-xs text-sentinel-muted mt-1">
            Before: {verResult.before_count} events {'->'}
            After: {verResult.after_count} events
            {verResult.delta_pct !== undefined && (
              <span className={
                verResult.delta_pct >= 0.8
                  ? ' text-green-400'
                  : verResult.delta_pct >= 0.2
                  ? ' text-amber-400'
                  : ' text-red-400'
              }>
                {' '}({Math.round(verResult.delta_pct * 100)}%
                reduction)
              </span>
            )}
          </div>
        )}

        {status === 'ROLLBACK_RECOMMENDED' && (
          <div className="text-xs text-red-400 mt-1">
            ! Events increased after execution - consider rollback
          </div>
        )}

        {status === 'PARTIAL_EFFECT' && (
          <div className="text-xs text-amber-400 mt-1">
            ~ Partial containment - some events still present
          </div>
        )}
      </div>
    )
  }

  const handleSendMessage = async (e) => {
    if (e) e.preventDefault()
    if (!inputValue.trim() || isStreaming) return

    const userText = inputValue.trim()
    setInputValue('')
    
    // Add user message locally
    const userMsg = {
      id: `user-${Date.now()}`,
      sender: 'user',
      text: userText,
      timestamp: new Date().toISOString()
    }
    
    setChatMessages(prev => [...prev, userMsg])
    setIsStreaming(true)
    
    // Placeholder for assistant
    const assistantMsgId = `assistant-${Date.now()}`
    setChatMessages(prev => [...prev, {
      id: assistantMsgId,
      sender: 'assistant',
      text: '',
      timestamp: new Date().toISOString()
    }])

    try {
      const response = await fetch(`/api/investigations/${investigationId}/containment-plan/chat`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: userText })
      })

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`)
      }

      const reader = response.body.getReader()
      const decoder = new TextDecoder()
      let accumText = ''
      let currentEvent = null
      let buffer = ''

      while (true) {
        const { value, done } = await reader.read()
        if (done) break
        
        buffer += decoder.decode(value, { stream: true })
        const lines = buffer.split('\n')
        buffer = lines.pop() || ''
        
        for (const line of lines) {
          const trimmed = line.trim()
          if (!trimmed) continue
          
          if (trimmed.startsWith('event:')) {
            currentEvent = trimmed.slice(6).trim()
          } else if (trimmed.startsWith('data:')) {
            const dataStr = trimmed.slice(5).trim()
            
            if (currentEvent === 'response_token') {
              try {
                const payload = JSON.parse(dataStr)
                accumText += payload.token || ''
                setChatMessages(prev => prev.map(msg => 
                  msg.id === assistantMsgId ? { ...msg, text: accumText } : msg
                ))
              } catch (err) {}
            } else if (currentEvent === 'response_complete') {
              try {
                const payload = JSON.parse(dataStr)
                setChatMessages(prev => prev.map(msg => 
                  msg.id === assistantMsgId ? { 
                    ...msg, 
                    text: payload.reply || accumText,
                    added_action: payload.added_action,
                    deleted_action_id: payload.deleted_action_id,
                    added_actions: payload.added_actions,
                    deleted_actions: payload.deleted_actions
                  } : msg
                ))
              } catch (err) {}
            } else if (currentEvent === 'plan_updated') {
              try {
                const payload = JSON.parse(dataStr)
                if (payload.plan) {
                  setLocalPlan(payload.plan)
                  onUpdate(payload.plan)
                }
              } catch (err) {}
            }
          }
        }
      }
    } catch (err) {
      console.error('Chat error:', err)
      setChatMessages(prev => prev.map(msg => 
        msg.id === assistantMsgId ? { 
          ...msg, 
          text: `Error connecting to Sentinel Copilot: ${err.message || 'Unknown error'}` 
        } : msg
      ))
    } finally {
      setIsStreaming(false)
    }
  }

  const [showConfirm, setShowConfirm] = useState(null) // phaseIdx

  const handleConfirmExecute = (phaseIdx) => {
    setShowConfirm(phaseIdx)
  }

  const proceedWithExecution = async () => {
    const pIdx = showConfirm
    setShowConfirm(null)
    await executePhase(pIdx)
  }

  if (!localPlan || !localPlan.phases) return null

  return (
    <div className="bg-sentinel-surface border border-sentinel-border rounded-xl p-6 mt-6">
      {/* Confirmation Modal */}
      {showConfirm !== null && (
        <div className="fixed inset-0 z-[100] flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm animate-fade-in">
          <div className="bg-sentinel-surface border border-sentinel-border rounded-2xl w-full max-w-lg shadow-2xl overflow-hidden">
          <div className="p-6 border-b border-sentinel-border">
              <div className="flex items-center gap-3 mb-2">
                <div className="w-10 h-10 rounded-full bg-sentinel-accent/10 flex items-center justify-center">
                  <Shield className="w-5 h-5 text-sentinel-accent" />
                </div>
                <div>
                  <h3 className="text-lg font-bold text-white">Execute Phase {showConfirm + 1}</h3>
                  <p className="text-xs text-sentinel-muted">{localPlan.phases?.[showConfirm]?.name || 'Unknown Phase'}</p>
                </div>
              </div>
            </div>
            
            <div className="p-6">
              <p className="text-sm text-sentinel-muted mb-4">
                The following remediation actions will be executed in Splunk. Please review the SPL logic below:
              </p>
              
              <div className="space-y-3 max-h-60 overflow-y-auto pr-2 custom-scrollbar">
                {asArray(localPlan.phases?.[showConfirm]?.actions).map((action) => (
                  <div key={action.id} className="bg-sentinel-bg rounded-lg p-3 border border-sentinel-border/50">
                    <div className="flex items-center gap-2 mb-2">
                      <div className="w-1.5 h-1.5 rounded-full bg-sentinel-accent" />
                      <span className="text-[10px] font-bold text-white uppercase">{action.title}</span>
                    </div>
                    <code className="text-[10px] font-mono text-sentinel-accent/90 break-all leading-relaxed block bg-black/20 p-2 rounded">
                      {String(action.containment_spl || '').replace('{{target}}', action.target || '')}
                    </code>
                  </div>
                ))}
              </div>

              <div className="mt-6 flex items-center gap-3">
                <button 
                  onClick={() => setShowConfirm(null)}
                  className="flex-1 px-4 py-2.5 bg-sentinel-surface border border-sentinel-border hover:bg-sentinel-border text-white rounded-xl text-sm font-medium transition-all"
                >
                  Cancel
                </button>
                <button 
                  onClick={proceedWithExecution}
                  className="flex-1 px-4 py-2.5 bg-sentinel-accent hover:bg-blue-500 text-white rounded-xl text-sm font-bold shadow-lg shadow-blue-500/20 transition-all"
                >
                  Confirm & Execute
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      <div className="flex items-center justify-between mb-6 border-b border-sentinel-border pb-4">
        <div className="flex items-center gap-2">
          <Shield className="w-5 h-5 text-sentinel-accent" />
          <h3 className="text-sm font-semibold text-white uppercase tracking-wider">Containment Plan & Copilot</h3>
          <span className="text-[10px] text-sentinel-muted bg-sentinel-bg px-2 py-0.5 rounded border border-sentinel-border uppercase">
            3-Phase Remediation
          </span>
        </div>
        <button 
          onClick={saveChanges}
          className="text-[10px] font-bold text-sentinel-accent hover:text-white transition-colors"
        >
          SAVE TARGET EDITS
        </button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        {/* Left column - Timeline */}
        <div className="lg:col-span-2 space-y-6">
          {asArray(localPlan.phases).map((phase, pIdx) => (
            <div key={pIdx} className="relative">
              {pIdx < localPlan.phases.length - 1 && (
                <div className="absolute left-4 top-10 bottom-0 w-px bg-sentinel-border" />
              )}
              
              <div className="flex items-start gap-4">
                <div className={`w-8 h-8 rounded-full flex items-center justify-center shrink-0 border-2 z-10 
                  ${phase.status === 'EXECUTED' ? 'bg-green-500/20 border-green-500 text-green-400' : 
                    phase.status === 'EXECUTING' ? 'bg-blue-500/20 border-blue-500 text-blue-400 animate-pulse' : 
                    'bg-sentinel-bg border-sentinel-border text-sentinel-muted'}`}>
                  {phase.status === 'EXECUTED' ? <CheckCircle2 className="w-4 h-4" /> : <span className="text-xs font-bold">{pIdx + 1}</span>}
                </div>

                <div className="flex-1 min-w-0">
                  <div className="flex items-center justify-between mb-2">
                    <div>
                      <h4 className="text-sm font-bold text-white">{phase.name}</h4>
                      <p className="text-xs text-sentinel-muted">{phase.description}</p>
                    </div>
                    {phase.status === 'PENDING' && (
                      <button 
                        onClick={() => handleConfirmExecute(pIdx)}
                        disabled={executingPhase !== null}
                        className="flex items-center gap-1.5 px-3 py-1 bg-sentinel-accent hover:bg-blue-500 text-white rounded-lg text-[10px] font-bold transition-all disabled:opacity-30"
                      >
                        <Play className="w-3 h-3 fill-current" /> EXECUTE PHASE
                      </button>
                    )}
                  </div>

                  <div className="space-y-2 mt-3">
                    {asArray(phase.actions).map((action, aIdx) => (
                      <div key={action.action_id || action.id || `${pIdx}-${aIdx}`} className="bg-sentinel-bg border border-sentinel-border rounded-lg p-3 group">
                        <div className="flex items-center justify-between mb-2">
                          <div className="flex items-center gap-2">
                            {action.status === 'EXECUTED' ? <CheckCircle2 className="w-3 h-3 text-green-400" /> : 
                             action.status === 'EXECUTING' || progress[action.id] === 'running' ? <Loader2 className="w-3 h-3 text-blue-400 animate-spin" /> :
                             <Circle className="w-3 h-3 text-sentinel-muted" />}
                            <span className="text-xs font-semibold text-white">{action.title}</span>
                          </div>
                          <div className="flex items-center gap-2">
                            {canRollback(action) && (
                              <button 
                                onClick={() => handleRollback(action.action_id || action.id)}
                                className="text-[9px] text-red-400/60 hover:text-red-400 flex items-center gap-1 transition-colors"
                              >
                                <RotateCcw className="w-2.5 h-2.5" /> ROLLBACK
                              </button>
                            )}
                            {getStatusBadge(action)}
                          </div>
                        </div>

                        <div className="flex items-center gap-3">
                          <div className="flex-1">
                            <label className="text-[9px] text-sentinel-muted uppercase block mb-1">Target Entity</label>
                            <input 
                              type="text" 
                              value={action.target}
                              onChange={(e) => handleTargetChange(pIdx, aIdx, e.target.value)}
                              disabled={action.status !== 'PENDING'}
                              className="w-full bg-sentinel-surface border border-sentinel-border rounded px-2 py-1 text-xs text-white focus:outline-none focus:border-sentinel-accent transition-colors disabled:opacity-50"
                            />
                          </div>
                          <div className="flex-1">
                            <label className="text-[9px] text-sentinel-muted uppercase block mb-1">Remediation Action</label>
                            <div className="text-xs text-white truncate font-mono opacity-80">{action.type}</div>
                          </div>
                        </div>
                        
                        {action.error && (
                          <div className="mt-2 text-[10px] text-red-400 bg-red-400/5 p-1.5 rounded border border-red-400/20">
                            {action.error}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          ))}
        </div>

        {/* Right column - Copilot Chat */}
        <div className="lg:col-span-1 border-t lg:border-t-0 lg:border-l border-sentinel-border/50 pt-6 lg:pt-0 lg:pl-6 flex flex-col h-[550px]">
          <div className="flex items-center justify-between mb-4 pb-2 border-b border-sentinel-border/30">
            <div className="flex items-center gap-2">
              <Sparkles className="w-4 h-4 text-sentinel-accent animate-pulse" />
              <span className="text-xs font-bold text-white uppercase tracking-wider">Refinement Copilot</span>
            </div>
            {isStreaming && (
              <span className="flex items-center gap-1 text-[9px] text-sentinel-accent uppercase font-bold tracking-tight">
                <Loader2 className="w-3 h-3 animate-spin" />
                Streaming
              </span>
            )}
          </div>

          <div ref={chatContainerRef} className="flex-1 overflow-y-auto mb-4 space-y-3 pr-2 custom-scrollbar flex flex-col">
            {chatMessages.length === 0 ? (
              <div className="flex flex-col items-center justify-center h-full text-center text-sentinel-muted">
                <Loader2 className="w-5 h-5 text-sentinel-accent animate-spin mb-2" />
                <p className="text-xs">Initializing refinement chat...</p>
              </div>
            ) : (
              chatMessages.map((msg, i) => (
                <div 
                  key={msg.id || i}
                  className={`flex flex-col max-w-[85%] ${msg.sender === 'user' ? 'self-end items-end' : 'self-start items-start'}`}
                >
                  <div 
                    className={`rounded-2xl px-3.5 py-2.5 text-xs leading-relaxed ${
                      msg.sender === 'user'
                        ? 'bg-sentinel-accent text-white rounded-tr-none'
                        : 'bg-sentinel-bg/60 border border-sentinel-border text-gray-200 rounded-tl-none'
                    }`}
                  >
                    {msg.text}
                    
                    {/* Legacy singular render for old messages */}
                    {msg.added_action && !msg.added_actions?.length && (
                      <div className="mt-2.5 bg-green-500/10 border border-green-500/20 rounded-lg p-2 text-[10px] text-green-400">
                        <div className="font-bold uppercase tracking-wider mb-1">
                          Added Action:
                        </div>
                        <div className="flex justify-between mb-0.5">
                          <span className="text-white/60">Type:</span>
                          <span className="font-mono">{msg.added_action.type}</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-white/60">Target:</span>
                          <span className="font-mono text-white">{msg.added_action.target}</span>
                        </div>
                      </div>
                    )}

                    {/* New array rendering */}
                    {msg.added_actions && msg.added_actions.map((act, idx) => (
                      <div key={`add-${idx}`} className="mt-2.5 bg-green-500/10 border border-green-500/20 rounded-lg p-2 text-[10px] text-green-400">
                        <div className="font-bold uppercase tracking-wider mb-1">
                          Added Action:
                        </div>
                        <div className="flex justify-between mb-0.5">
                          <span className="text-white/60">Type:</span>
                          <span className="font-mono">{act.type}</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-white/60">Target:</span>
                          <span className="font-mono text-white">{act.target}</span>
                        </div>
                      </div>
                    ))}

                    {/* Legacy singular render for old messages */}
                    {msg.deleted_action_id && !msg.deleted_actions?.length && (
                      <div className="mt-2.5 bg-red-500/10 border border-red-500/20 rounded-lg p-2 text-[10px] text-red-400">
                        <div className="font-bold uppercase tracking-wider mb-1">
                          Removed Action:
                        </div>
                        <div className="flex justify-between">
                          <span className="text-white/60">Action ID:</span>
                          <span className="font-mono text-white">#{msg.deleted_action_id.slice(0, 8)}</span>
                        </div>
                      </div>
                    )}

                    {/* New array rendering */}
                    {msg.deleted_actions && msg.deleted_actions.map((act, idx) => (
                      <div key={`del-${idx}`} className="mt-2.5 bg-red-500/10 border border-red-500/20 rounded-lg p-2 text-[10px] text-red-400">
                        <div className="font-bold uppercase tracking-wider mb-1">
                          Removed Action:
                        </div>
                        <div className="flex justify-between mb-0.5">
                          <span className="text-white/60">Type:</span>
                          <span className="font-mono text-white">{act.type || 'Unknown'}</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-white/60">Target:</span>
                          <span className="font-mono text-white">{act.target || act.id || 'Unknown'}</span>
                        </div>
                      </div>
                    ))}
                  </div>
                  <span className="text-[9px] text-sentinel-muted mt-1 px-1">
                    {msg.timestamp ? new Date(msg.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : ''}
                  </span>
                </div>
              ))
            )}
            <div ref={messagesEndRef} />
          </div>

          <form onSubmit={handleSendMessage} className="mt-auto">
            {validationWarning && (
              <div className="bg-amber-500/10 border border-amber-500/20 text-amber-400 rounded-lg p-2 mb-2 text-[9px] leading-normal flex items-start gap-1.5 animate-pulse">
                <AlertCircle className="w-3.5 h-3.5 shrink-0 mt-0.5" />
                <span>{validationWarning}</span>
              </div>
            )}
            
            <div className="relative">
              <input 
                type="text"
                value={inputValue}
                onChange={(e) => setInputValue(e.target.value)}
                disabled={isStreaming}
                placeholder={isStreaming ? "AI Copilot is streaming response..." : "Ask Copilot to add/delete/modify actions..."}
                className="w-full bg-sentinel-bg border border-sentinel-border rounded-xl pl-3 pr-10 py-2.5 text-xs text-white focus:outline-none focus:border-sentinel-accent transition-colors disabled:opacity-50"
              />
              <button 
                type="submit"
                disabled={isStreaming || !inputValue.trim()}
                className="absolute right-1.5 top-1/2 -translate-y-1/2 p-1.5 bg-sentinel-accent hover:bg-blue-500 text-white rounded-lg transition-all disabled:opacity-30 disabled:hover:bg-sentinel-accent flex items-center justify-center"
              >
                <Send className="w-3.5 h-3.5" />
              </button>
            </div>
          </form>
        </div>
      </div>
    </div>
  )
}

function ConfidenceBreakdownPanel({ investigationId }) {
  const [breakdown, setBreakdown] = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    if (!investigationId) return

    let cancelled = false
    setLoading(true)

    fetch(`/api/investigations/${investigationId}/confidence-breakdown`)
      .then(res => res.ok ? res.json() : null)
      .then(data => {
        if (cancelled) return
        setBreakdown(data)
        setLoading(false)
      })
      .catch(() => {
        if (!cancelled) setLoading(false)
      })

    return () => {
      cancelled = true
    }
  }, [investigationId])

  if (loading || !breakdown || !breakdown.factors) return null

  const CONFIDENCE_TONE_MAP = {
    high: { bar: 'bg-green-500', text: 'text-green-400', border: 'border-green-500/30', badge: 'bg-green-500/10 text-green-400 border-green-500/30' },
    medium: { bar: 'bg-amber-500', text: 'text-amber-400', border: 'border-amber-500/30', badge: 'bg-amber-500/10 text-amber-400 border-amber-500/30' },
    low: { bar: 'bg-red-500', text: 'text-red-400', border: 'border-red-500/30', badge: 'bg-red-500/10 text-red-400 border-red-500/30' },
  }
  const getScoreTone = (score) => {
    if (score >= 0.75) return CONFIDENCE_TONE_MAP.high
    if (score >= 0.50) return CONFIDENCE_TONE_MAP.medium
    return CONFIDENCE_TONE_MAP.low
  }

  const weakestName = breakdown.weakest_factor?.name
  const strongestName = breakdown.strongest_factor?.name
  const overallScore = breakdown.overall || 0
  const overallPct = Math.round(overallScore * 100)
  const overallTone = getScoreTone(overallScore)

  return (
    <div className="bg-sentinel-surface border border-sentinel-border rounded-xl p-6" style={{ borderTop: '2px solid #3b82f6' }}>
      <div className="flex flex-col gap-4 md:flex-row md:items-start md:justify-between mb-6">
        <div>
          <div className="flex items-center gap-2 mb-2">
            <div className="w-2 h-4 rounded-sm bg-sentinel-accent" />
            <h3 className="text-sm font-bold text-white tracking-wide">
              Confidence Score Breakdown
            </h3>
          </div>
          <p className="text-xs text-sentinel-muted ml-4">
            Deterministic reconstruction confidence, shown by weighted evidence factor.
          </p>
        </div>

        <div className="bg-sentinel-bg border border-sentinel-border rounded-lg px-4 py-3 min-w-[150px]">
          <div className={`text-4xl font-bold leading-none ${overallTone.text}`}>
            {overallPct}%
          </div>
          <div className="h-2 w-full rounded-full bg-sentinel-surface border border-sentinel-border overflow-hidden mt-2 mb-1">
            <div
              className={`h-full ${overallTone.bar}`}
              style={{ width: `${overallPct}%` }}
            />
          </div>
          <div className="flex items-center justify-between gap-3">
            <div className="text-[10px] text-sentinel-muted uppercase tracking-widest">
              Overall Score
            </div>
            <div className="text-[10px] text-sentinel-muted">
              {breakdown.factors.length} factors evaluated
            </div>
          </div>
        </div>
      </div>

      <div className="space-y-3">
        {breakdown.factors.map((factor) => {
          const rawScore = factor.raw_score || 0
          const rawPct = Math.round(rawScore * 100)
          const weightPct = Math.round((factor.weight || 0) * 100)
          const contributionPct = Math.round((factor.contribution || 0) * 100)
          const tone = getScoreTone(rawScore)
          const isWeakest = factor.name === weakestName
          const isStrongest = factor.name === strongestName

          return (
            <div
              key={factor.name}
              className={`border rounded-lg p-4 ${
                isWeakest
                  ? 'border-amber-500/40 bg-amber-500/5'
                  : isStrongest
                    ? 'border-green-500/40 bg-green-500/5'
                    : 'border-sentinel-border bg-sentinel-bg'
              }`}
            >
              <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-2 mb-1">
                    <span className="text-sm font-semibold text-white">
                      {factor.name}
                    </span>
                    {isWeakest && (
                      <span className="flex items-center gap-1 text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded border border-amber-500/30 bg-amber-500/10 text-amber-400">
                        <span className="w-1.5 h-1.5 rounded-full bg-amber-400 shrink-0" />
                        Confidence Gap
                      </span>
                    )}
                    {isStrongest && (
                      <span className="flex items-center gap-1 text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded border border-green-500/30 bg-green-500/10 text-green-400">
                        <span className="w-1.5 h-1.5 rounded-full bg-green-400 shrink-0" />
                        Strongest Signal
                      </span>
                    )}
                  </div>
                  <p className="text-xs text-sentinel-muted leading-relaxed">
                    {factor.description}
                  </p>
                  <p className="text-[11px] text-sentinel-muted/70 mt-1 font-mono">
                    {factor.detail}
                  </p>
                  {isStrongest && (
                    <p className="text-[10px] text-green-400/70 mt-2 uppercase tracking-wider">
                      Primary supporting evidence
                    </p>
                  )}
                  {isWeakest && (
                    <p className="text-[10px] text-amber-400/70 mt-2 uppercase tracking-wider">
                      Missing validation signal
                    </p>
                  )}
                </div>

                <div className="w-full md:w-72">
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-[10px] uppercase tracking-wider text-sentinel-muted">
                      Contributes
                    </span>
                    <span className={`text-lg font-bold leading-none ${tone.text}`}>
                      {contributionPct}%
                    </span>
                  </div>
                  <div className="h-2 rounded-full bg-sentinel-surface border border-sentinel-border overflow-hidden">
                    <div
                      className={`h-full ${tone.bar}`}
                      style={{ width: `${contributionPct}%` }}
                    />
                  </div>
                  <div className="grid grid-cols-2 gap-2 mt-2">
                    <div className="rounded border border-sentinel-border bg-sentinel-surface px-2 py-1">
                      <div className="text-xs text-sentinel-muted">
                        Raw {rawPct}%
                      </div>
                    </div>
                    <div className="rounded border border-sentinel-border bg-sentinel-surface px-2 py-1">
                      <div className="text-xs text-sentinel-muted">
                        Weight {weightPct}%
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )
        })}
      </div>

      {breakdown.weakest_factor?.recommendation && (
        <div className="mt-4 border border-amber-500/30 bg-amber-500/10 rounded-lg p-4">
          <div className="flex items-start justify-between gap-3 mb-2">
            <div className="flex items-center gap-2">
              <div className="w-1.5 h-1.5 rounded-full bg-amber-400" />
              <div className="text-[10px] font-bold uppercase tracking-wider text-amber-400">
                Next Confidence Lift
              </div>
            </div>
            <span className="text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded border border-amber-500/30 bg-sentinel-bg text-amber-300">
              Actionable Gap
            </span>
          </div>
          <p className="text-sm text-white leading-relaxed">
            <span className="text-amber-300 font-semibold">
              {breakdown.weakest_factor.name || 'Confidence gap'}
            </span>
            {': '}
            {breakdown.weakest_factor.recommendation}
          </p>
          <p className="text-xs text-sentinel-muted mt-2">
            Completing this check can improve the confidence score.
          </p>
        </div>
      )}
    </div>
  )
}

function MltkEnrichmentStatus({
  investigationId,
  onEnrichmentComplete,
}) {
  const [status, setStatus] = useState('pending')
  const [summary, setSummary] = useState(null)
  const intervalRef = useRef(null)
  const pollCountRef = useRef(0)
  const consecutiveErrorCountRef = useRef(0)
  const hasCompletedRef = useRef(false)
  const MAX_POLLS = 40
  const MAX_CONSECUTIVE_ERRORS = 3

  useEffect(() => {
    if (!investigationId) return
    pollCountRef.current = 0
    consecutiveErrorCountRef.current = 0
    hasCompletedRef.current = false

    const pollOnce = async () => {
      if (hasCompletedRef.current) return
      try {
        pollCountRef.current += 1
        const res = await fetch(
          `/api/investigations/${investigationId}/ttp-enrichment`
        )
        if (!res.ok) {
          consecutiveErrorCountRef.current += 1
          if (
            consecutiveErrorCountRef.current >= MAX_CONSECUTIVE_ERRORS &&
            intervalRef.current
          ) {
            clearInterval(intervalRef.current)
            intervalRef.current = null
            setStatus('failed')
          }
          return
        }

        const data = await res.json()
        consecutiveErrorCountRef.current = 0
        setStatus(data.status)

        if (data.status === 'complete') {
          hasCompletedRef.current = true
          setSummary(data.summary || {})
          if (intervalRef.current) {
            clearInterval(intervalRef.current)
            intervalRef.current = null
          }
          if (onEnrichmentComplete && data.ttp_mappings?.length) {
            onEnrichmentComplete(data.ttp_mappings)
          }
          return
        }

        if (data.status === 'pending' || data.status === 'running') {
          if (pollCountRef.current >= MAX_POLLS) {
            if (intervalRef.current) {
              clearInterval(intervalRef.current)
              intervalRef.current = null
            }
            setStatus('timed_out')
            return
          }
          if (!intervalRef.current) {
            intervalRef.current = setInterval(pollOnce, 3000)
          }
          return
        }

        if (intervalRef.current) {
          clearInterval(intervalRef.current)
          intervalRef.current = null
        }
      } catch {
        consecutiveErrorCountRef.current += 1
        if (
          consecutiveErrorCountRef.current >= MAX_CONSECUTIVE_ERRORS &&
          intervalRef.current
        ) {
          clearInterval(intervalRef.current)
          intervalRef.current = null
          setStatus('failed')
        }
      }
    }

    pollOnce()

    return () => {
      if (intervalRef.current) {
        clearInterval(intervalRef.current)
        intervalRef.current = null
      }
    }
  }, [investigationId, onEnrichmentComplete])

  if (status === 'pending' || status === 'running') {
    return (
      <div className="flex items-center gap-2 mt-2">
        <div
          className="w-3 h-3 border-2 border-blue-500 border-t-transparent
                     rounded-full animate-spin"
        />
        <span className="text-xs text-sentinel-muted">
          Validating techniques with Splunk MLTK...
        </span>
      </div>
    )
  }

  if (status === 'complete' && summary) {
    const hasDisagreements = (summary.disagreements || 0) > 0
    return (
      <div className="flex items-center gap-3 mt-2">
        <span className="text-xs text-green-400">
          MLTK validated {summary.techniques_validated || 0} techniques
        </span>
        <span className="text-xs text-sentinel-muted">
          {summary.agreements || 0} agreements
        </span>
        {hasDisagreements && (
          <span className="text-xs text-amber-400">
            {summary.disagreements} disagreements
          </span>
        )}
      </div>
    )
  }

  return null
}

const FEEDBACK_RATINGS = [
  {
    key: 'correct',
    label: 'Correct',
    shortLabel: 'Correct',
    icon: 'OK',
    description: 'Investigation is accurate',
    activeClass: 'border-green-500 bg-green-500/10 text-green-400',
    inactiveClass: 'border-sentinel-border text-sentinel-muted hover:border-green-500/50',
  },
  {
    key: 'partial',
    label: 'Partially Correct',
    shortLabel: 'Partial',
    icon: '~',
    description: 'Some findings need correction',
    activeClass: 'border-amber-500 bg-amber-500/10 text-amber-400',
    inactiveClass: 'border-sentinel-border text-sentinel-muted hover:border-amber-500/50',
  },
  {
    key: 'incorrect',
    label: 'Incorrect',
    shortLabel: 'Incorrect',
    icon: 'X',
    description: 'Classification or evidence is wrong',
    activeClass: 'border-red-500 bg-red-500/10 text-red-400',
    inactiveClass: 'border-sentinel-border text-sentinel-muted hover:border-red-500/50',
  },
]

const FEEDBACK_NOTE_COPY = {
  correct: {
    title: 'Validation Note',
    helper: 'Optional: add context that confirms what the investigation got right.',
    placeholder: 'Optional: note what was accurate or useful in this investigation.',
  },
  partial: {
    title: 'Correction Needed',
    helper: 'Describe the specific finding, timeline detail, or evidence point that needs correction.',
    placeholder: 'Describe what needs correction, such as patient zero, impacted asset, or missing evidence.',
  },
  incorrect: {
    title: 'Ground Truth Correction',
    helper: 'Describe the correct classification or evidence so the evaluation dataset can learn from it.',
    placeholder: 'Describe what was wrong and provide the correct ground truth if known.',
  },
}

function FeedbackCard({
  feedbackRating,
  setFeedbackRating,
  feedbackNotes,
  setFeedbackNotes,
  feedbackStatus,
  onSubmit,
}) {
  if (feedbackStatus === 'submitted') {
    return (
      <div className="bg-sentinel-surface border border-green-500/30 
                      rounded-xl p-6 mt-6"
           style={{ borderTop: '2px solid #10b981' }}>
        <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
          <div className="flex items-start gap-3">
          <div className="w-8 h-8 bg-green-500/20 rounded-full 
                          flex items-center justify-center flex-shrink-0">
            <span className="text-green-400 font-bold">OK</span>
          </div>
          <div>
            <p className="text-sm font-semibold text-green-400">
              Feedback submitted
            </p>
            <p className="text-xs text-sentinel-muted mt-0.5">
              This investigation has been saved to the evaluation dataset.
            </p>
            <div className="flex gap-2 flex-wrap mt-3">
              <span className="text-xs px-2 py-1 rounded 
                               bg-sentinel-bg border
                               border-sentinel-border
                               text-sentinel-muted">
                Human validation captured
              </span>
              <span className="text-xs px-2 py-1 rounded 
                               bg-sentinel-bg border
                               border-sentinel-border
                               text-sentinel-muted">
                Calibration signal recorded
              </span>
            </div>
          </div>
          </div>
          <span className="text-xs px-2 py-1 rounded 
                           bg-green-500/10 border
                           border-green-500/30 text-green-400
                           whitespace-nowrap">
            Evaluation Updated
          </span>
        </div>
      </div>
    )
  }

  const selectedRating = FEEDBACK_RATINGS.find(
    (rating) => rating.key === feedbackRating
  )
  const noteCopy = feedbackRating
    ? FEEDBACK_NOTE_COPY[feedbackRating] ?? FEEDBACK_NOTE_COPY.correct
    : null

  return (
    <div className="bg-sentinel-surface border border-sentinel-border 
                    rounded-xl p-6 mt-6"
         style={{ borderTop: '2px solid #3b82f6' }}>
      {/* Header */}
      <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between mb-4">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <div className="w-2 h-4 rounded-sm bg-sentinel-accent" />
            <h3 className="text-sm font-bold text-white tracking-wide">
              Analyst Feedback
            </h3>
          </div>
          <p className="text-xs text-sentinel-muted ml-4">
            Human validation used to calibrate future confidence scores
          </p>
        </div>
        <span className="text-xs px-2 py-1 rounded bg-sentinel-bg border border-sentinel-border text-sentinel-muted whitespace-nowrap">
          Evaluation Dataset
        </span>
      </div>

      <p className="text-xs text-sentinel-muted mb-4">
        Was this autonomous investigation accurate? Your rating 
        is stored in Supabase and used to calibrate future 
        confidence scores.
      </p>

      {/* Rating buttons */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 mb-4">
        {FEEDBACK_RATINGS.map((rating) => (
          <button
            key={rating.key}
            onClick={() => setFeedbackRating(rating.key)}
            disabled={feedbackStatus === 'submitting'}
            className={`flex flex-col items-start gap-2 p-3 rounded-lg 
                        border text-left transition-all
                        disabled:opacity-50 disabled:cursor-not-allowed
                        ${feedbackRating === rating.key
                          ? rating.activeClass
                          : rating.inactiveClass
                        }`}
          >
            <div className="flex items-center gap-2">
              <span className="text-xs font-bold px-1.5 py-0.5 rounded bg-sentinel-bg border border-sentinel-border">
                {rating.icon}
              </span>
              <span className="text-sm font-semibold">
                {rating.label}
              </span>
            </div>
            <p className="text-xs opacity-80 leading-relaxed">
              {rating.description}
            </p>
          </button>
        ))}
      </div>

      {/* Notes input - only shown when rating selected */}
      {selectedRating && noteCopy && (
        <div className="bg-sentinel-bg rounded-lg p-4 mb-4">
          <div className="flex items-start justify-between gap-3 mb-3">
            <div>
              <div className="text-[10px] font-bold text-sentinel-muted 
                              uppercase tracking-wider">
                Analyst Notes
              </div>
              <p className="text-xs text-sentinel-muted mt-1">
                {noteCopy.helper}
              </p>
            </div>
            <span className={`text-xs px-2 py-0.5 rounded border 
                              shrink-0 ${selectedRating.activeClass}`}>
              {selectedRating.label}
            </span>
          </div>
          <textarea
            value={feedbackNotes}
            onChange={(e) => setFeedbackNotes(e.target.value)}
            placeholder={noteCopy.placeholder}
            disabled={feedbackStatus === 'submitting'}
            rows={3}
            className="w-full bg-sentinel-bg border border-sentinel-border 
                       rounded-lg px-3 py-2 text-sm text-white 
                       placeholder:text-sentinel-muted/50
                       focus:outline-none focus:border-sentinel-accent
                       resize-none disabled:opacity-50
                       transition-colors"
          />
          <p className="text-xs text-sentinel-muted mt-2 opacity-70">
            Saved as evaluation context for future calibration.
          </p>
        </div>
      )}

      {/* Submit button */}
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        {feedbackStatus === 'error' ? (
          <p className="text-xs text-red-400">
            Failed to submit feedback. Please try again.
          </p>
        ) : (
          <p className="text-xs text-sentinel-muted">
            {!feedbackRating
              ? 'Select a verdict to enable submission'
              : feedbackNotes.trim().length > 0
                ? 'Ready to submit verdict + notes'
                : 'Ready to submit verdict'}
          </p>
        )}
        <button
          onClick={onSubmit}
          disabled={!feedbackRating || feedbackStatus === 'submitting'}
          className={`flex items-center gap-2 px-4 py-2 rounded-lg 
                      text-sm font-medium transition-all
                      ${!feedbackRating || feedbackStatus === 'submitting'
                        ? 'bg-sentinel-surface border border-sentinel-border opacity-40 cursor-not-allowed'
                        : 'bg-sentinel-accent hover:bg-blue-500 text-white cursor-pointer shadow-sm shadow-blue-500/20'
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

const CLASSIFICATION_COLORS = {
  APT:            'text-red-400 border-red-500/30 bg-red-500/5',
  RANSOMWARE:     'text-orange-400 border-orange-500/30 bg-orange-500/5',
  INSIDER_THREAT: 'text-purple-400 border-purple-500/30 bg-purple-500/5',
  BRUTE_FORCE:    'text-amber-400 border-amber-500/30 bg-amber-500/5',
  UNKNOWN:        'text-gray-400 border-gray-500/30 bg-gray-500/5',
}

const CLASSIFICATION_LEFT_BORDERS = {
  APT: 'border-l-red-500',
  RANSOMWARE: 'border-l-orange-500',
  INSIDER_THREAT: 'border-l-purple-500',
  BRUTE_FORCE: 'border-l-amber-500',
  UNKNOWN: 'border-l-gray-500',
}

const CLASSIFICATION_LABELS = {
  APT: 'APT',
  RANSOMWARE: 'Ransomware',
  INSIDER_THREAT: 'Insider Threat',
  BRUTE_FORCE: 'Brute Force',
  UNKNOWN: 'Unknown',
}

const normalizeClassification = (value) => {
  const normalized = String(value || '')
    .trim()
    .toUpperCase()
    .replace(/[\s-]+/g, '_')

  return normalized || 'UNKNOWN'
}

const getClassificationLabel = (value) => {
  const normalized = normalizeClassification(value)
  if (CLASSIFICATION_LABELS[normalized]) {
    return CLASSIFICATION_LABELS[normalized]
  }

  return normalized
    .toLowerCase()
    .split('_')
    .filter(Boolean)
    .map((part) => part[0].toUpperCase() + part.slice(1))
    .join(' ') || CLASSIFICATION_LABELS.UNKNOWN
}

const normalizeMissingIndicators = (indicators) => {
  if (!Array.isArray(indicators)) return []

  return indicators
    .map((indicator) => String(indicator || '').trim())
    .filter(Boolean)
}

function CounterfactualCard({ counterfactual, confirmedClassification }) {
  const alternativesRaw = Array.isArray(counterfactual?.alternatives_ruled_out)
    ? counterfactual.alternatives_ruled_out
    : []
  const alternatives = alternativesRaw
    .filter((alt) => alt && typeof alt === 'object')
    .map((alt, index) => {
      const classificationKey = normalizeClassification(alt.classification)

      return {
        classificationKey,
        classificationLabel: getClassificationLabel(classificationKey),
        reason:
          typeof alt.reason === 'string' && alt.reason.trim()
            ? alt.reason.trim()
            : 'No counterfactual reasoning was provided.',
        missingIndicators: normalizeMissingIndicators(alt.missing_indicators),
        originalIndex: index,
      }
    })

  if (!alternatives.length) {
    return null
  }

  const confirmedKey = normalizeClassification(confirmedClassification)
  const confirmedLabel = getClassificationLabel(confirmedKey)

  return (
    <div className="bg-sentinel-surface border border-sentinel-border
                    rounded-xl p-6 mt-6"
         style={{ borderTop: '2px solid #3b82f6' }}>
      {/* Header */}
      <div className="flex flex-col gap-3 md:flex-row md:items-start md:justify-between mb-4">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <div className="w-2 h-4 rounded-sm bg-sentinel-accent" />
            <h3 className="text-sm font-bold text-white tracking-wide">
              Why This Classification?
            </h3>
          </div>
          <p className="text-xs text-sentinel-muted ml-4">
            Confirmed by ruling out competing classifications
          </p>
        </div>
        <span className="text-xs px-2 py-1 rounded bg-sentinel-bg border border-sentinel-border text-sentinel-muted whitespace-nowrap">
          {alternatives.length} ruled out
        </span>
      </div>

      {/* Confirmed */}
      <div className="bg-sentinel-bg border border-sentinel-border rounded-lg p-4 mb-4">
        <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <div className="text-[10px] font-bold uppercase tracking-wider text-sentinel-muted mb-1">
              Confirmed Classification
            </div>
            <div className="text-lg font-bold text-white leading-tight">
              {confirmedLabel}
            </div>
            <div className="text-xs text-sentinel-muted mt-1">
              Selected after counterfactual elimination
            </div>
          </div>
          <span className={`text-xs font-bold px-2 py-1 rounded border w-fit ${
            CLASSIFICATION_COLORS[confirmedKey]
            || CLASSIFICATION_COLORS.UNKNOWN
          }`}>
            CONFIRMED
          </span>
        </div>
      </div>

      {/* Ruled out alternatives */}
      <div className="flex items-center justify-between mb-2">
        <span className="text-[10px] font-bold uppercase tracking-wider text-sentinel-muted">
          Ruled-Out Alternatives
        </span>
        <span className="text-xs text-sentinel-muted">
          {alternatives.length} checks
        </span>
      </div>
      <div className="space-y-3">
        {alternatives.map((alt, index) => {
          const isLast = index === alternatives.length - 1

          return (
          <div key={alt.originalIndex} className="flex gap-3">
            <div className="flex flex-col items-center pt-4">
              <div className="w-6 h-6 rounded-full border border-sentinel-accent/40 bg-sentinel-bg text-[10px] font-bold text-blue-300 flex items-center justify-center shadow-sm">
                {String(index + 1).padStart(2, '0')}
              </div>
              {!isLast && (
                <div className="w-px flex-1 bg-sentinel-border mt-2" />
              )}
            </div>
          <div
            className={`border border-sentinel-border border-l-4 ${
              CLASSIFICATION_LEFT_BORDERS[alt.classificationKey]
              || CLASSIFICATION_LEFT_BORDERS.UNKNOWN
            } rounded-lg p-4 bg-sentinel-bg`}
          >
            <div className="flex items-center gap-2 mb-2 flex-wrap">
              <span className={`text-xs font-bold px-2 py-0.5 
                                rounded border ${
                                  CLASSIFICATION_COLORS[alt.classificationKey]
                                  || CLASSIFICATION_COLORS.UNKNOWN
                                }`}>
                {alt.classificationLabel} Ruled Out
              </span>
              <span className="text-xs px-2 py-0.5 rounded border border-sentinel-border bg-sentinel-surface text-sentinel-muted">
                Counterfactual
              </span>
            </div>

            <p className="text-xs text-sentinel-muted leading-relaxed mb-2">
              {alt.reason}
            </p>

            {alt.missingIndicators.length > 0 && (
              <div className="flex flex-wrap gap-1 mt-2">
                <span className="text-xs text-sentinel-muted/60 mr-1">
                  Absent Signals
                </span>
                {alt.missingIndicators.map((ind, j) => (
                  <span
                    key={j}
                    className="text-xs font-mono px-1.5 py-0.5
                               bg-sentinel-surface border
                               border-sentinel-border rounded
                               text-sentinel-muted/80"
                  >
                    {ind}
                  </span>
                ))}
              </div>
            )}
          </div>
          </div>
          )
        })}
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
        Audit verification unavailable
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
        <span>{isValid ? 'LOCK' : 'WARN'}</span>
        <span>
          {isValid
            ? `Audit Chain Verified - ${totalEntries} entries`
            : `Chain Integrity Failure - Entry ${brokenIndex} modified`
          }
        </span>
        <span className={`transition-transform ${expanded ? 'rotate-180' : ''}`}>
          v
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
              {isValid ? 'INTACT' : 'BROKEN'}
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
                        {entry.was_corrected ? 'corrected' : 'clean'}
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

function DetectionGapPanel({ investigationId }) {
  const [gaps, setGaps] = useState(null)
  const [loading, setLoading] = useState(false)
  const [analysisStep, setAnalysisStep] = useState(0)
  const [error, setError] = useState(null)
  const [expanded, setExpanded] = useState(true)
  const [expandedGaps, setExpandedGaps] = useState({})
  const [copied, setCopied] = useState({})
  const [deploying, setDeploying] = useState({})
  const [deployed, setDeployed] = useState({})

  const analysisStages = [
    'Inventorying mapped MITRE techniques',
    'Comparing against Splunk saved searches',
    'Identifying uncovered techniques',
    'Generating detection SPL',
  ]

  useEffect(() => {
    if (!loading) {
      setAnalysisStep(0)
      return undefined
    }

    setAnalysisStep(0)
    const intervalId = setInterval(() => {
      setAnalysisStep(prev => (prev + 1) % analysisStages.length)
    }, 900)

    return () => clearInterval(intervalId)
  }, [loading, analysisStages.length])

  const fetchGaps = async () => {
    if (!investigationId) return
    setLoading(true)
    setError(null)
    try {
      const res = await fetch(`/api/investigations/${investigationId}/detection-gaps`)
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      const data = await res.json()
      setGaps(data)
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  const handleCopy = (techId, spl) => {
    navigator.clipboard.writeText(spl).then(() => {
      setCopied(prev => ({ ...prev, [techId]: true }))
      setTimeout(() => setCopied(prev => ({ ...prev, [techId]: false })), 2000)
    })
  }

  const handleDeploy = async (gap) => {
    const techId = gap.technique_id
    setDeploying(prev => ({ ...prev, [techId]: true }))
    try {
      const res = await fetch(
        `/api/investigations/${investigationId}/detection-gaps/deploy`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            technique_id: techId,
            spl: gap.recommended_spl,
            name: gap.recommended_name,
          }),
        }
      )
      const data = await res.json()
      if (!res.ok) throw new Error(data.detail || 'Deploy failed')
      setDeployed(prev => ({ ...prev, [techId]: { success: true, message: data.message } }))
    } catch (err) {
      setDeployed(prev => ({ ...prev, [techId]: { success: false, error: err.message } }))
    } finally {
      setDeploying(prev => ({ ...prev, [techId]: false }))
    }
  }

  const toggleGap = (techId) => {
    setExpandedGaps(prev => ({ ...prev, [techId]: !prev[techId] }))
  }

  const scoreColor = (score) => {
    if (score >= 0.75) return 'text-green-400'
    if (score >= 0.50) return 'text-amber-400'
    if (score >= 0.25) return 'text-orange-400'
    return 'text-red-400'
  }

  const labelBg = (label) => {
    if (!label) return 'border-sentinel-border text-sentinel-muted'
    if (label.includes('GOOD')) return 'border-green-500/30 text-green-400 bg-green-500/5'
    if (label.includes('PARTIAL')) return 'border-amber-500/30 text-amber-400 bg-amber-500/5'
    if (label.includes('SIGNIFICANT')) return 'border-orange-500/30 text-orange-400 bg-orange-500/5'
    return 'border-red-500/30 text-red-400 bg-red-500/5'
  }

  return (
    <div
      className="mt-8 border border-sentinel-border rounded-2xl bg-sentinel-surface overflow-hidden"
      style={{ borderTop: '2px solid #3b82f6' }}
    >
      {/* Header */}
      <div
        className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between px-6 py-4 cursor-pointer
                   hover:bg-sentinel-bg/30 transition-colors"
        onClick={() => setExpanded(e => !e)}
      >
        <div>
          <div className="flex items-center gap-2 mb-1">
            <div className="w-2 h-4 rounded-sm bg-sentinel-accent" />
            <span className="text-sm font-bold text-white tracking-wide">
              Detection Gap Analysis
            </span>
          </div>
          <p className="text-xs text-sentinel-muted ml-4">
            Find uncovered MITRE techniques and generate Splunk detection SPL
          </p>
        </div>
        <div className="flex items-center gap-3">
          {gaps && (
            <>
              <span className={`text-[11px] font-mono font-bold px-2 py-0.5
                               rounded border ${labelBg(gaps.coverage_label)}`}>
                {gaps.coverage_label}
              </span>
              <span className={`text-xs font-mono font-bold ${scoreColor(gaps.coverage_score)}`}>
                {Math.round(gaps.coverage_score * 100)}% COVERED
              </span>
            </>
          )}
          {!gaps && !loading && (
            <button
              onClick={(e) => { e.stopPropagation(); fetchGaps() }}
              className="px-3 py-1.5 text-[11px] font-semibold uppercase tracking-wider
                         bg-sentinel-accent/10 border border-sentinel-accent/30
                         rounded-lg text-sentinel-accent
                         hover:bg-sentinel-accent/20 transition-colors"
            >
              Analyze Coverage
            </button>
          )}
          {loading && (
            <span className="text-xs text-sentinel-muted animate-pulse">Analyzing...</span>
          )}
          <span className="text-sentinel-muted text-xs">{expanded ? '^' : 'v'}</span>
        </div>
      </div>

      {/* Body */}
      {expanded && (
        <div className="px-6 pb-6 space-y-6 border-t border-sentinel-border">

          {/* Error */}
          {error && (
            <div className="mt-4 p-3 rounded-lg border border-red-500/30 bg-red-500/5">
              <p className="text-xs text-red-400">Error: {error}</p>
              <button
                onClick={fetchGaps}
                className="mt-2 text-[11px] text-sentinel-accent hover:underline"
              >
                Retry
              </button>
            </div>
          )}

          {/* Idle prompt */}
          {!gaps && !loading && !error && (
            <div className="mt-4 bg-sentinel-bg rounded-lg p-5">
              <div className="mb-4">
                <h4 className="text-sm font-semibold text-white">
                  Coverage Analysis Ready
                </h4>
                <p className="text-xs text-sentinel-muted mt-1 leading-relaxed">
                  Compare mapped ATT&amp;CK techniques against deployed Splunk
                  saved searches and generate missing detection SPL.
                </p>
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 mb-4">
                <div className="bg-sentinel-surface border border-sentinel-border rounded-lg p-3">
                  <p className="text-xs font-semibold text-white">
                    MITRE Coverage
                  </p>
                  <p className="text-xs text-sentinel-muted mt-1">
                    Mapped techniques
                  </p>
                </div>
                <div className="bg-sentinel-surface border border-sentinel-border rounded-lg p-3">
                  <p className="text-xs font-semibold text-white">
                    Saved Search Match
                  </p>
                  <p className="text-xs text-sentinel-muted mt-1">
                    Splunk coverage
                  </p>
                </div>
                <div className="bg-sentinel-surface border border-sentinel-border rounded-lg p-3">
                  <p className="text-xs font-semibold text-white">
                    Detection SPL
                  </p>
                  <p className="text-xs text-sentinel-muted mt-1">
                    Recommended searches
                  </p>
                </div>
              </div>
              <button
                onClick={fetchGaps}
                className="px-4 py-2 text-xs font-semibold uppercase tracking-wider
                           bg-sentinel-accent/10 border border-sentinel-accent/30
                           rounded-lg text-sentinel-accent
                           hover:bg-sentinel-accent/20 transition-colors"
              >
                Run Detection Gap Analysis
              </button>
            </div>
          )}

          {/* Loading */}
          {loading && (
            <div className="mt-4 bg-sentinel-bg rounded-lg p-5">
              <div className="flex items-center gap-2 mb-2">
                <span className="w-2 h-2 rounded-full bg-sentinel-accent animate-pulse" />
                <h4 className="text-sm font-semibold text-white">
                  Analyzing Coverage
                </h4>
              </div>
              <p className="text-xs text-sentinel-muted leading-relaxed mb-4">
                Checking mapped ATT&amp;CK techniques against deployed Splunk saved searches.
              </p>
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
                {analysisStages.map((stage, idx) => {
                  const isActive = idx === analysisStep
                  const isComplete = idx < analysisStep
                  return (
                    <div
                      key={stage}
                      className={
                        isActive
                          ? "bg-sentinel-surface border border-sentinel-accent/40 rounded-lg p-3"
                          : isComplete
                            ? "bg-sentinel-surface border border-green-500/20 rounded-lg p-3"
                            : "bg-sentinel-surface border border-sentinel-border rounded-lg p-3 opacity-50"
                      }
                    >
                      <div className="flex items-center gap-2">
                        <span
                          className={
                            isActive
                              ? "w-2 h-2 rounded-full bg-sentinel-accent shrink-0"
                              : isComplete
                                ? "w-2 h-2 rounded-full bg-green-400/70 shrink-0"
                                : "w-2 h-2 rounded-full bg-sentinel-muted/40 shrink-0"
                          }
                        />
                        <p
                          className={
                            isActive
                              ? "text-xs font-semibold text-white"
                              : isComplete
                                ? "text-xs font-semibold text-green-400/80"
                                : "text-xs font-semibold text-sentinel-muted"
                          }
                        >
                          {stage}
                        </p>
                      </div>
                    </div>
                  )
                })}
              </div>
            </div>
          )}

          {/* Results */}
          {gaps && !loading && (
            <>
              {/* Summary row */}
              <div className="mt-4 space-y-3">
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
                  <div className="border border-sentinel-border rounded-xl p-3 bg-sentinel-bg">
                    <p className="text-[10px] text-sentinel-muted uppercase tracking-wider mb-1">
                      Techniques Analyzed
                    </p>
                    <p className="text-xl font-bold font-mono text-white">
                      {gaps.techniques_analyzed}
                    </p>
                    <p className="text-[10px] text-sentinel-muted mt-1">
                      mapped
                    </p>
                  </div>
                  <div className="border border-sentinel-border rounded-xl p-3 bg-sentinel-bg">
                    <p className="text-[10px] text-sentinel-muted uppercase tracking-wider mb-1">
                      Covered
                    </p>
                    <p className="text-xl font-bold font-mono text-green-400">
                      {gaps.covered}
                    </p>
                    <p className="text-[10px] text-sentinel-muted mt-1">
                      matched
                    </p>
                  </div>
                  <div className="border border-sentinel-border rounded-xl p-3 bg-sentinel-bg">
                    <p className="text-[10px] text-sentinel-muted uppercase tracking-wider mb-1">
                      Gaps Found
                    </p>
                    <p className="text-xl font-bold font-mono text-red-400">
                      {gaps.not_covered}
                    </p>
                    <p className="text-[10px] text-sentinel-muted mt-1">
                      uncovered
                    </p>
                  </div>
                  <div className="border border-sentinel-border rounded-xl p-3 bg-sentinel-bg">
                    <p className="text-[10px] text-sentinel-muted uppercase tracking-wider mb-1">
                      Saved Searches Checked
                    </p>
                    <p className="text-xl font-bold font-mono text-white">
                      {gaps.saved_searches_checked ?? '-'}
                    </p>
                    <p className="text-[10px] text-sentinel-muted mt-1">
                      searched
                    </p>
                  </div>
                </div>
                <div className="border border-sentinel-border rounded-xl p-3 bg-sentinel-bg">
                  <div className="flex items-center justify-between gap-3 mb-2">
                    <span className="text-[10px] text-sentinel-muted uppercase tracking-wider">
                      Coverage posture
                    </span>
                    <span className={`text-xs font-mono font-bold ${scoreColor(gaps.coverage_score)}`}>
                      {Math.round(gaps.coverage_score * 100)}%
                    </span>
                  </div>
                  <div className="h-2 rounded-full bg-sentinel-surface border border-sentinel-border overflow-hidden">
                    {gaps.coverage_score >= 0.75 && (
                      <div
                        className="h-full bg-green-500 rounded-full"
                        style={{ width: `${Math.round(gaps.coverage_score * 100)}%` }}
                      />
                    )}
                    {gaps.coverage_score >= 0.50 && gaps.coverage_score < 0.75 && (
                      <div
                        className="h-full bg-amber-500 rounded-full"
                        style={{ width: `${Math.round(gaps.coverage_score * 100)}%` }}
                      />
                    )}
                    {gaps.coverage_score >= 0.25 && gaps.coverage_score < 0.50 && (
                      <div
                        className="h-full bg-orange-500 rounded-full"
                        style={{ width: `${Math.round(gaps.coverage_score * 100)}%` }}
                      />
                    )}
                    {gaps.coverage_score < 0.25 && (
                      <div
                        className="h-full bg-red-500 rounded-full"
                        style={{ width: `${Math.round(gaps.coverage_score * 100)}%` }}
                      />
                    )}
                  </div>
                </div>
              </div>

              {/* Gaps */}
              {gaps.gaps && gaps.gaps.length > 0 && (
                <div>
                  <p className="text-xs font-semibold text-red-400 uppercase tracking-wider mb-3">
                    Uncovered Techniques - {gaps.gaps.length} Gap{gaps.gaps.length !== 1 ? 's' : ''}
                  </p>
                  <div className="space-y-3">
                    {gaps.gaps.map(gap => (
                      <div key={gap.technique_id}
                           className="border border-red-500/20 rounded-xl bg-red-500/5 overflow-hidden">
                        {/* Gap header */}
                        <div
                          className="flex items-center justify-between px-4 py-3
                                     cursor-pointer hover:bg-red-500/10 transition-colors"
                          onClick={() => toggleGap(gap.technique_id)}
                        >
                          <div className="flex items-center gap-2 flex-wrap">
                            <span className="text-[10px] font-bold text-red-400 uppercase">
                              Detection Gap
                            </span>
                            <span className="text-xs font-mono font-bold text-sentinel-accent">
                              {gap.technique_id}
                            </span>
                            <span className="text-xs text-white">{gap.technique_name}</span>
                            <span className="text-xs px-1.5 py-0.5 rounded
                                             border border-sentinel-border
                                             bg-sentinel-bg text-sentinel-muted">
                              {gap.tactic}
                            </span>
                          </div>
                          <div className="flex items-center gap-2 shrink-0">
                            {gap.recommended_spl && (
                              <span className="text-[10px] font-bold
                                               text-amber-300 border
                                               border-amber-500/30
                                               bg-amber-500/10 rounded
                                               px-2 py-0.5">
                                SPL Ready
                              </span>
                            )}
                            <span className="text-sentinel-muted text-xs">
                              {expandedGaps[gap.technique_id] ? '^' : 'v'}
                            </span>
                          </div>
                        </div>

                        {/* Gap SPL */}
                        {expandedGaps[gap.technique_id] && gap.recommended_spl && (
                          <div className="px-4 pb-4">
                            <div className="flex items-center justify-between mb-2">
                              <div>
                                <span className="text-[10px] font-bold text-white uppercase tracking-wider">
                                  Generated Detection SPL
                                </span>
                                <p className="text-[10px] text-sentinel-muted font-mono mt-0.5">
                                  method: {gap.generation_method}
                                </p>
                              </div>
                              <div className="flex gap-2">
                                <button
                                  onClick={() => handleCopy(gap.technique_id, gap.recommended_spl)}
                                  className="px-2 py-1 text-[10px]
                                             bg-sentinel-bg border border-sentinel-border
                                             rounded text-sentinel-muted
                                             hover:text-white hover:border-sentinel-accent
                                             transition-colors"
                                >
                                  {copied[gap.technique_id] ? 'Copied!' : 'Copy SPL'}
                                </button>
                                <button
                                  onClick={() => handleDeploy(gap)}
                                  disabled={deploying[gap.technique_id] || deployed[gap.technique_id]?.success}
                                  className="px-2 py-1 text-[10px]
                                             bg-amber-500/10 border border-amber-500/30
                                             rounded text-amber-400
                                             hover:bg-amber-500/20
                                             disabled:opacity-50
                                             transition-colors"
                                >
                                  {deploying[gap.technique_id]
                                    ? 'Deploying...'
                                    : deployed[gap.technique_id]?.success
                                      ? 'Deployed'
                                      : 'Deploy as Saved Search'}
                                </button>
                              </div>
                            </div>

                            <pre className="bg-sentinel-bg border border-sentinel-border
                                           rounded-lg p-3 text-xs font-mono text-sentinel-accent
                                           overflow-x-auto whitespace-pre">
                              {gap.recommended_spl}
                            </pre>
                            <p className="text-xs text-sentinel-muted mt-2">
                              Review and tune before production deployment.
                            </p>

                            {deployed[gap.technique_id] && (
                              <div className="mt-2 text-[11px]">
                                {deployed[gap.technique_id].success ? (
                                  <span className="text-green-400">
                                    OK {deployed[gap.technique_id].message || 'Successfully deployed!'}
                                  </span>
                                ) : (
                                  <span className="text-red-400">
                                    Error: {deployed[gap.technique_id].error}
                                  </span>
                                )}
                              </div>
                            )}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Covered techniques */}
              {gaps.covered_techniques && gaps.covered_techniques.length > 0 && (
                <div>
                  <p className="text-xs font-semibold text-green-400 uppercase tracking-wider mb-3">
                    Covered Techniques
                  </p>
                  <div className="space-y-2">
                    {gaps.covered_techniques.map(tech => (
                      <div key={tech.technique_id}
                           className="border border-green-500/20 rounded-xl p-3
                                      bg-green-500/5 flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <span className="text-xs font-bold text-green-400">COVERED</span>
                          <span className="text-xs font-mono text-sentinel-accent">
                            {tech.technique_id}
                          </span>
                          <span className="text-xs text-white">{tech.technique_name}</span>
                          <span className="text-xs text-sentinel-muted">- {tech.tactic}</span>
                        </div>
                        <div className="flex items-center gap-2">
                          <span className="text-[10px] text-sentinel-muted">Confidence:</span>
                          <span className={`text-[10px] font-bold font-mono px-1.5 py-0.5
                                          rounded border
                                          ${
                                            tech.match_confidence === 'HIGH'
                                              ? 'border-green-500/30 text-green-400 bg-green-500/5'
                                              : tech.match_confidence === 'MEDIUM'
                                                ? 'border-amber-500/30 text-amber-400 bg-amber-500/5'
                                                : 'border-sentinel-border text-sentinel-muted bg-sentinel-bg'
                                          }`}>
                            {tech.match_confidence}
                          </span>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </>
          )}
        </div>
      )}
    </div>
  )
}

export default function ReportPage() {
  const { id } = useParams()
  const { state, dispatch } = useInvestigation()
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
  const [enrichedTtpMappings, setEnrichedTtpMappings] = useState(null)

  // Use state.result if available, otherwise use historicalData
  const activeResult = state.result || historicalData
  const report = activeResult?.final_report
  const safeKillChainStages = (() => {
    // Try all three data sources in priority order
    // Live investigation: state.result.kill_chain
    // Historical report: report_json.kill_chain_stages
    // Fallback: report.kill_chain_stages
    const candidates = [
      state.result?.kill_chain,
      activeResult?.report_json?.kill_chain_stages,
      report?.kill_chain_stages,
    ]

    // Use first candidate that is a real array
    const raw = candidates.find(Array.isArray) || []

    // Filter out non-objects and numbers
    // kill_chain_stages can be a count (number)
    // at the top level of the Supabase row
    // Only keep actual stage objects
    return raw.filter(
      (stage) =>
        stage !== null &&
        stage !== undefined &&
        typeof stage === 'object' &&
        !Array.isArray(stage)
    )
  })()
  const ttpData = enrichedTtpMappings || activeResult?.ttp_mappings || []

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

  const handleEnrichmentComplete = useCallback((enrichedMappings) => {
    setEnrichedTtpMappings(enrichedMappings)
  }, [])

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

  const normalizedSeverity =
    REPORT_SEVERITY_TONES[normalizeReportToken(report.severity)]
      ? normalizeReportToken(report.severity)
      : 'HIGH'
  const normalizedClassification =
    REPORT_CLASSIFICATION_TONES[normalizeReportToken(report.classification)]
      ? normalizeReportToken(report.classification)
      : 'UNKNOWN'
  const reportInvestigationId =
    report.investigation_id ||
    activeResult?.investigation_id ||
    id ||
    state.investigationId
  const primaryConfidence =
    report.confidence?.primary ??
    report.confidence_breakdown?.overall ??
    report.investigation_confidence ??
    0
  const confidencePct = Math.round(primaryConfidence * 100)
  const confidenceLabel =
    report.confidence?.primary_label || 'Evidence Confidence'
  const sloStatus =
    report.slo_report?.overall_slo_status === 'ALL_MET' ? 'PASS' : 'BREACH'
  const sloTone = REPORT_SLO_TONES[sloStatus] || REPORT_SLO_TONES.BREACH
  const safeContainmentPlan = normalizeContainmentPlan(report.containment_plan)
  const safeMitreTechniques = asArray(report.mitre_techniques_used).filter(
    (technique) => typeof technique === 'string' && technique.trim().length > 0
  )
  const safeRecommendedActions = asArray(report.recommended_actions)
  const safeKeyFindings = asArray(report.key_findings)
  const safeCves = asArray(report.cves_identified)

  return (
    <div className="max-w-5xl mx-auto px-6 py-8 animate-fade-in">
      {/* Report header */}
      <div className="mb-6">
        <button
          onClick={() => navigate('/dashboard')}
          className="flex items-center gap-2 text-sm text-sentinel-muted hover:text-white mb-4 transition-colors group"
        >
          <ArrowLeft className="w-4 h-4 group-hover:-translate-x-1 transition-transform" /> Back to Dashboard
        </button>
        <div
          className={
            normalizedSeverity === 'CRITICAL'
              ? "bg-sentinel-surface border border-sentinel-border border-t-2 border-t-sentinel-danger rounded-xl p-5 shadow-lg"
              : normalizedSeverity === 'HIGH'
                ? "bg-sentinel-surface border border-sentinel-border border-t-2 border-t-orange-400 rounded-xl p-5 shadow-lg"
                : normalizedSeverity === 'MEDIUM'
                  ? "bg-sentinel-surface border border-sentinel-border border-t-2 border-t-sentinel-warning rounded-xl p-5 shadow-lg"
                  : "bg-sentinel-surface border border-sentinel-border border-t-2 border-t-sentinel-success rounded-xl p-5 shadow-lg"
          }
        >
          <div className="flex flex-col gap-5 lg:flex-row lg:items-start lg:justify-between">
            <div>
              <div className="flex items-center gap-3 mb-2">
                <span className={`text-[10px] font-bold px-2.5 py-0.5 rounded-full border uppercase tracking-wider ${
                  REPORT_SEVERITY_TONES[normalizedSeverity]
                }`}>
                  {report.severity}
                </span>
                <span className={`text-[10px] font-mono border px-2.5 py-0.5 rounded-full uppercase tracking-wider ${
                  REPORT_CLASSIFICATION_TONES[normalizedClassification]
                }`}>
                  {report.classification || normalizedClassification}
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
                <span>-</span>
                <span>{report.generated_at ? new Date(report.generated_at).toLocaleString() : 'Just now'}</span>
              </p>
            </div>
            <div className="flex items-center gap-4 flex-wrap lg:justify-end">
              <div className="text-right mr-4 border-r border-sentinel-border pr-6">
                <div className="text-3xl font-bold text-sentinel-accent leading-none">
                  {confidencePct}%
                </div>
                <div className="text-[10px] text-sentinel-muted uppercase tracking-widest mt-1">{confidenceLabel}</div>
                
                {/* SLO Status Pill */}
                {report.slo_report && (
                  <div className="mt-4 flex justify-end group/slo relative">
                    <div 
                      className={`flex items-center gap-1.5 px-2 py-0.5 rounded-full border cursor-help transition-all
                        ${sloTone.chip}`}
                      title="System Performance Compliance"
                    >
                      <Zap className={`w-2.5 h-2.5 ${sloTone.icon}`} />
                      <span className="text-[10px] font-bold font-mono tracking-tight">
                        SLO: {sloStatus}
                      </span>
                    </div>

                    {/* Refined Glassmorphism Tooltip */}
                    <div className="absolute top-full right-0 mt-3 w-52 p-4 
                                    bg-sentinel-surface/95 backdrop-blur-xl 
                                    border border-sentinel-border rounded-xl 
                                    shadow-[0_20px_50px_rgba(0,0,0,0.5)] opacity-0 translate-y-1 
                                    pointer-events-none group-hover/slo:opacity-100 
                                    group-hover/slo:translate-y-0 transition-all duration-200 z-50">
                      <div className="flex items-center gap-2 mb-3 border-b border-sentinel-border pb-2">
                        <Zap className="w-3 h-3 text-sentinel-accent" />
                        <p className="text-[10px] font-bold text-white uppercase tracking-wider">
                          Performance Metrics
                        </p>
                      </div>
                      
                      <div className="space-y-2.5">
                        <div className="flex justify-between items-center text-[10px]">
                          <span className="text-sentinel-muted">Wall-clock Time</span>
                          <span className={`font-mono ${report.slo_report.slo_1_time?.met ? 'text-green-400' : 'text-red-400 font-bold'}`}>
                            {report.slo_report.slo_1_time?.actual_seconds}s <span className="opacity-40">/ {report.slo_report.slo_1_time?.budget_seconds}s</span>
                          </span>
                        </div>
                        <div className="flex justify-between items-center text-[10px]">
                          <span className="text-sentinel-muted">Token Budget</span>
                          <span className={`font-mono ${report.slo_report.slo_2_tokens?.met ? 'text-green-400' : 'text-red-400 font-bold'}`}>
                            {Math.round(report.slo_report.slo_2_tokens?.actual_tokens / 1000)}k <span className="opacity-40">/ {Math.round(report.slo_report.slo_2_tokens?.budget_tokens / 1000)}k</span>
                          </span>
                        </div>

                        {report.slo_report.slo_breaches?.length > 0 && (
                          <div className="mt-2 pt-2 border-t border-sentinel-border/50">
                            <div className="flex items-start gap-1.5">
                              <AlertCircle className="w-3 h-3 text-red-400 shrink-0 mt-0.5" />
                              <p className="text-[9px] text-red-400/90 leading-relaxed italic">
                                {report.slo_report.slo_breaches[0]}
                              </p>
                            </div>
                          </div>
                        )}
                      </div>

                      <div className="mt-3 pt-2 text-[8px] text-sentinel-muted italic border-t border-sentinel-border/30 text-right">
                        Verified by SLO Engine v1.2
                      </div>
                    </div>
                  </div>
                )}
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
        </div>
      </div>

      {/* Report sections */}
      <div className="space-y-6">
        {/* Kill Chain Timeline - first thing judges see */}
        {safeKillChainStages.length > 0 && (
          <RouteSectionErrorBoundary sectionName="KillChainTimeline">
            <KillChainTimeline stages={safeKillChainStages} />
          </RouteSectionErrorBoundary>
        )}

        <RouteSectionErrorBoundary sectionName="ExecutiveSummary">
          <ExecutiveSummary report={report} />
        </RouteSectionErrorBoundary>

        <RouteSectionErrorBoundary sectionName="ConfidenceBreakdown">
          <ConfidenceBreakdownPanel investigationId={reportInvestigationId} />
        </RouteSectionErrorBoundary>
        
        <RouteSectionErrorBoundary sectionName="FindingsGrid">
          <FindingsGrid findings={safeKeyFindings} />
        </RouteSectionErrorBoundary>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <RouteSectionErrorBoundary sectionName="RecommendedActions">
            <RecommendedActions actions={safeRecommendedActions} />
          </RouteSectionErrorBoundary>
          <RouteSectionErrorBoundary sectionName="CveList">
            <CveList cves={safeCves} />
          </RouteSectionErrorBoundary>
        </div>

        <RouteSectionErrorBoundary sectionName="ContainmentPlanPanel">
          <ContainmentPlanPanel 
            investigationId={reportInvestigationId}
            plan={safeContainmentPlan}
            onUpdate={(newPlan) => {
              if (state.result) {
                dispatch({ type: 'UPDATE_CONTAINMENT_PLAN', plan: newPlan })
              } else if (historicalData) {
                setHistoricalData(prev => ({
                  ...prev,
                  final_report: {
                    ...prev.final_report,
                    containment_plan: newPlan
                  }
                }))
              }
            }}
          />
        </RouteSectionErrorBoundary>

        <RouteSectionErrorBoundary sectionName="MltkEnrichmentStatus">
          <MltkEnrichmentStatus
            investigationId={reportInvestigationId}
            onEnrichmentComplete={handleEnrichmentComplete}
          />
        </RouteSectionErrorBoundary>

        <RouteSectionErrorBoundary sectionName="MitreTable">
          <MitreTable
            techniques={safeMitreTechniques}
            ttpMappings={ttpData}
          />
        </RouteSectionErrorBoundary>

        <RouteSectionErrorBoundary sectionName="DetectionGapPanel">
          <DetectionGapPanel
            investigationId={reportInvestigationId}
          />
        </RouteSectionErrorBoundary>
        
        <RouteSectionErrorBoundary sectionName="ThreatIntelCards">
          <ThreatIntelCards threatIntel={activeResult?.threat_intel || {}} />
        </RouteSectionErrorBoundary>
        
        {/* Counterfactual Reasoning */}
        {report?.counterfactual_reasoning && (
          <RouteSectionErrorBoundary sectionName="CounterfactualCard">
            <CounterfactualCard
              counterfactual={report.counterfactual_reasoning}
              confirmedClassification={report.classification}
            />
          </RouteSectionErrorBoundary>
        )}

        {/* Analyst Feedback */}
        <RouteSectionErrorBoundary sectionName="FeedbackCard">
          <FeedbackCard
            feedbackRating={feedbackRating}
            setFeedbackRating={setFeedbackRating}
            feedbackNotes={feedbackNotes}
            setFeedbackNotes={setFeedbackNotes}
            feedbackStatus={feedbackStatus}
            onSubmit={handleSubmitFeedback}
          />
        </RouteSectionErrorBoundary>
        
        <div className="pt-8 text-center border-t border-sentinel-border opacity-30">
          <p className="text-[10px] text-sentinel-muted uppercase tracking-[0.2em]">
            End of Automated Incident Report - Splunk Sentinel
          </p>
        </div>
      </div>
    </div>
  )
}


