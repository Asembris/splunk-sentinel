import { useParams, useNavigate } from 'react-router-dom'
import { useState, useEffect, useRef } from 'react'
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


function ContainmentPlanPanel({ investigationId, plan, onUpdate }) {
  const [executingPhase, setExecutingPhase] = useState(null)
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
    setLocalPlan(plan)
  }, [plan])

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
        const events = buffer.split('\n\n')
        buffer = events.pop() || ''

        for (const eventText of events) {
          const dataLine = eventText
            .split('\n')
            .find(line => line.trim().startsWith('data:'))
          if (!dataLine) continue

          const data = JSON.parse(dataLine.slice(dataLine.indexOf(':') + 1).trim())
          console.debug('[CONTAINMENT SSE]', data)

          if (data.event === 'action_started') {
            setProgress(prev => ({ ...prev, [data.action_id]: 'running' }))
          } else if (data.event === 'action_complete') {
            setProgress(prev => ({ ...prev, [data.action_id]: 'success' }))
          } else if (data.event === 'action_failed') {
            setProgress(prev => ({ ...prev, [data.action_id]: 'error' }))
          } else if (data.event === 'phase_complete') {
            setLocalPlan(data.plan)
            onUpdate(data.plan)
          }
        }
      }
    } catch (err) {
      console.error('SSE Error:', err)
    } finally {
      setExecutingPhase(null)
    }
  }

  const handleRollback = async (actionId) => {
    try {
      const res = await fetch(`/api/investigations/${investigationId}/containment-plan/rollback?action_id=${actionId}`, {
        method: 'POST'
      })
      if (res.ok) {
        // Refresh plan
        const planRes = await fetch(`/api/investigations/${investigationId}/containment-plan`)
        const updatedPlan = await planRes.json()
        setLocalPlan(updatedPlan)
        onUpdate(updatedPlan)
      }
    } catch (err) {
      console.error('Rollback failed:', err)
    }
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
                  <p className="text-xs text-sentinel-muted">{localPlan.phases[showConfirm].name}</p>
                </div>
              </div>
            </div>
            
            <div className="p-6">
              <p className="text-sm text-sentinel-muted mb-4">
                The following remediation actions will be executed in Splunk. Please review the SPL logic below:
              </p>
              
              <div className="space-y-3 max-h-60 overflow-y-auto pr-2 custom-scrollbar">
                {localPlan.phases[showConfirm].actions.map((action) => (
                  <div key={action.id} className="bg-sentinel-bg rounded-lg p-3 border border-sentinel-border/50">
                    <div className="flex items-center gap-2 mb-2">
                      <div className="w-1.5 h-1.5 rounded-full bg-sentinel-accent" />
                      <span className="text-[10px] font-bold text-white uppercase">{action.title}</span>
                    </div>
                    <code className="text-[10px] font-mono text-sentinel-accent/90 break-all leading-relaxed block bg-black/20 p-2 rounded">
                      {action.containment_spl.replace('{{target}}', action.target)}
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
          {localPlan.phases.map((phase, pIdx) => (
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
                    {phase.actions.map((action, aIdx) => (
                      <div key={action.id} className="bg-sentinel-bg border border-sentinel-border rounded-lg p-3 group">
                        <div className="flex items-center justify-between mb-2">
                          <div className="flex items-center gap-2">
                            {action.status === 'EXECUTED' ? <CheckCircle2 className="w-3 h-3 text-green-400" /> : 
                             action.status === 'EXECUTING' || progress[action.id] === 'running' ? <Loader2 className="w-3 h-3 text-blue-400 animate-spin" /> :
                             <Circle className="w-3 h-3 text-sentinel-muted" />}
                            <span className="text-xs font-semibold text-white">{action.title}</span>
                          </div>
                          <div className="flex items-center gap-2">
                            {action.status === 'EXECUTED' && action.reversal_spl && (
                              <button 
                                onClick={() => handleRollback(action.id)}
                                className="text-[9px] text-red-400/60 hover:text-red-400 flex items-center gap-1 transition-colors"
                              >
                                <RotateCcw className="w-2.5 h-2.5" /> ROLLBACK
                              </button>
                            )}
                            <span className={`text-[9px] font-bold uppercase tracking-tighter px-1.5 py-0.5 rounded
                              ${action.status === 'EXECUTED' ? 'bg-green-500/10 text-green-400' : 
                                action.status === 'FAILED' ? 'bg-red-500/10 text-red-400' :
                                action.status === 'ROLLED_BACK' ? 'bg-amber-500/10 text-amber-400' :
                                'bg-sentinel-surface text-sentinel-muted'}`}>
                              {action.status}
                            </span>
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
                          ✓ Proposed Action Added:
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
                          ✓ Proposed Action Added:
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
                          ✗ Proposed Action Removed:
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
                          ✗ Proposed Action Removed:
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

  const scoreTone = (score) => {
    if (score >= 0.75) return 'bg-green-500 text-green-400 border-green-500/30'
    if (score >= 0.50) return 'bg-amber-500 text-amber-400 border-amber-500/30'
    return 'bg-red-500 text-red-400 border-red-500/30'
  }

  const weakestName = breakdown.weakest_factor?.name
  const strongestName = breakdown.strongest_factor?.name

  return (
    <div className="bg-sentinel-surface border border-sentinel-border rounded-xl p-6">
      <div className="flex flex-col gap-4 md:flex-row md:items-start md:justify-between mb-6">
        <div>
          <div className="flex items-center gap-2 mb-2">
            <div className="w-1.5 h-4 bg-sentinel-accent rounded-full" />
            <h3 className="text-sm font-semibold text-sentinel-muted uppercase tracking-wider">
              Confidence Score Breakdown
            </h3>
          </div>
          <p className="text-xs text-sentinel-muted">
            Deterministic reconstruction confidence, shown by weighted evidence factor.
          </p>
        </div>

        <div className="text-left md:text-right">
          <div className="text-4xl font-bold text-sentinel-accent leading-none">
            {Math.round((breakdown.overall || 0) * 100)}%
          </div>
          <div className="text-[10px] text-sentinel-muted uppercase tracking-widest mt-1">
            overall score
          </div>
        </div>
      </div>

      <div className="space-y-3">
        {breakdown.factors.map((factor) => {
          const rawScore = factor.raw_score || 0
          const tone = scoreTone(rawScore)
          const isWeakest = factor.name === weakestName
          const isStrongest = factor.name === strongestName

          return (
            <div
              key={factor.name}
              className={`border rounded-lg p-4 bg-sentinel-bg ${
                isWeakest
                  ? 'border-amber-500/40'
                  : isStrongest
                    ? 'border-green-500/40'
                    : 'border-sentinel-border'
              }`}
            >
              <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-2 mb-1">
                    <span className="text-sm font-semibold text-white">
                      {factor.name}
                    </span>
                    {isWeakest && (
                      <span className="text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded border border-amber-500/30 bg-amber-500/10 text-amber-400">
                        Weakest
                      </span>
                    )}
                    {isStrongest && (
                      <span className="text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded border border-green-500/30 bg-green-500/10 text-green-400">
                        Strongest
                      </span>
                    )}
                  </div>
                  <p className="text-xs text-sentinel-muted leading-relaxed">
                    {factor.description}
                  </p>
                  <p className="text-[11px] text-sentinel-muted/70 mt-1 font-mono">
                    {factor.detail}
                  </p>
                </div>

                <div className="w-full md:w-72">
                  <div className="flex items-center justify-between text-[10px] uppercase tracking-wider mb-1">
                    <span className="text-sentinel-muted">Raw score</span>
                    <span className={`font-mono font-bold ${tone.split(' ')[1]}`}>
                      {Math.round(rawScore * 100)}%
                    </span>
                  </div>
                  <div className="h-2 rounded-full bg-sentinel-surface border border-sentinel-border overflow-hidden">
                    <div
                      className={`h-full ${tone.split(' ')[0]}`}
                      style={{ width: `${Math.round(rawScore * 100)}%` }}
                    />
                  </div>
                  <div className="grid grid-cols-2 gap-2 mt-2">
                    <div className="rounded border border-sentinel-border bg-sentinel-surface px-2 py-1">
                      <div className="text-[9px] text-sentinel-muted uppercase">Weight</div>
                      <div className="text-xs font-mono text-white">
                        {Math.round((factor.weight || 0) * 100)}%
                      </div>
                    </div>
                    <div className="rounded border border-sentinel-border bg-sentinel-surface px-2 py-1">
                      <div className="text-[9px] text-sentinel-muted uppercase">Contribution</div>
                      <div className="text-xs font-mono text-white">
                        {Math.round((factor.contribution || 0) * 100)}%
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
          <div className="text-[10px] font-bold uppercase tracking-wider text-amber-400 mb-1">
            Recommended Confidence Improvement
          </div>
          <p className="text-sm text-white">
            {breakdown.weakest_factor.name}: {breakdown.weakest_factor.recommendation}
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

  useEffect(() => {
    if (!investigationId) return

    const pollOnce = async () => {
      try {
        const res = await fetch(
          `/api/investigations/${investigationId}/ttp-enrichment`
        )
        if (!res.ok) return

        const data = await res.json()
        setStatus(data.status)

        if (data.status === 'complete') {
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
        if (intervalRef.current) {
          clearInterval(intervalRef.current)
          intervalRef.current = null
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
          ✓ MLTK validated {summary.techniques_validated || 0} techniques
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

const CLASSIFICATION_COLORS = {
  APT:            'text-red-400 border-red-500/30 bg-red-500/5',
  RANSOMWARE:     'text-orange-400 border-orange-500/30 bg-orange-500/5',
  INSIDER_THREAT: 'text-purple-400 border-purple-500/30 bg-purple-500/5',
  BRUTE_FORCE:    'text-amber-400 border-amber-500/30 bg-amber-500/5',
  UNKNOWN:        'text-gray-400 border-gray-500/30 bg-gray-500/5',
}

function CounterfactualCard({ counterfactual, confirmedClassification }) {
  if (
    !counterfactual ||
    !counterfactual.alternatives_ruled_out ||
    counterfactual.alternatives_ruled_out.length === 0
  ) {
    return null
  }

  return (
    <div className="bg-sentinel-surface border border-sentinel-border
                    rounded-xl p-6 mt-6">
      {/* Header */}
      <div className="flex items-center gap-2 mb-4">
        <div className="w-1.5 h-4 bg-sentinel-accent rounded-full" />
        <h3 className="text-sm font-semibold text-sentinel-muted
                       uppercase tracking-wider">
          Why This Classification?
        </h3>
      </div>

      {/* Confirmed */}
      <div className="flex items-center gap-2 mb-4">
        <span className="text-xs text-sentinel-muted">Confirmed:</span>
        <span className={`text-xs font-bold px-2 py-0.5 rounded
                          border ${
                            CLASSIFICATION_COLORS[confirmedClassification]
                            || CLASSIFICATION_COLORS.UNKNOWN
                          }`}>
          ✓ {confirmedClassification}
        </span>
      </div>

      {/* Ruled out alternatives */}
      <div className="space-y-3">
        {counterfactual.alternatives_ruled_out.map((alt, i) => (
          <div
            key={i}
            className="border border-sentinel-border rounded-lg p-4
                       bg-sentinel-bg"
          >
            <div className="flex items-center gap-2 mb-2">
              <span className={`text-xs font-bold px-2 py-0.5 
                                rounded border ${
                                  CLASSIFICATION_COLORS[alt.classification]
                                  || CLASSIFICATION_COLORS.UNKNOWN
                                }`}>
                ✗ Not {alt.classification}
              </span>
            </div>

            <p className="text-xs text-sentinel-muted leading-relaxed mb-2">
              {alt.reason}
            </p>

            {alt.missing_indicators &&
             alt.missing_indicators.length > 0 && (
              <div className="flex flex-wrap gap-1 mt-2">
                <span className="text-xs text-sentinel-muted/60 mr-1">
                  Missing:
                </span>
                {alt.missing_indicators.map((ind, j) => (
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
        ))}
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

function DetectionGapPanel({ investigationId }) {
  const [gaps, setGaps] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const [expanded, setExpanded] = useState(true)
  const [expandedGaps, setExpandedGaps] = useState({})
  const [copied, setCopied] = useState({})
  const [deploying, setDeploying] = useState({})
  const [deployed, setDeployed] = useState({})

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
    <div className="mt-8 border border-sentinel-border rounded-2xl bg-sentinel-surface overflow-hidden">
      {/* Header */}
      <div
        className="flex items-center justify-between px-6 py-4 cursor-pointer
                   hover:bg-sentinel-bg/30 transition-colors"
        onClick={() => setExpanded(e => !e)}
      >
        <div className="flex items-center gap-3">
          <span className="text-sm font-bold text-white uppercase tracking-widest">
            Detection Gap Analysis
          </span>
          {gaps && (
            <span className={`text-[11px] font-mono font-bold px-2 py-0.5
                             rounded border ${labelBg(gaps.coverage_label)}`}>
              {gaps.coverage_label}
            </span>
          )}
        </div>
        <div className="flex items-center gap-3">
          {gaps && (
            <span className={`text-xs font-mono font-bold ${scoreColor(gaps.coverage_score)}`}>
              {Math.round(gaps.coverage_score * 100)}% COVERED
            </span>
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
            <span className="text-xs text-sentinel-muted animate-pulse">Analyzing…</span>
          )}
          <span className="text-sentinel-muted text-xs">{expanded ? '▲' : '▼'}</span>
        </div>
      </div>

      {/* Body */}
      {expanded && (
        <div className="px-6 pb-6 space-y-6 border-t border-sentinel-border">

          {/* Error */}
          {error && (
            <div className="mt-4 p-3 rounded-lg border border-red-500/30 bg-red-500/5">
              <p className="text-xs text-red-400">⚠ {error}</p>
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
            <div className="mt-4 text-center py-8">
              <p className="text-sm text-sentinel-muted mb-4">
                Identify MITRE ATT&amp;CK techniques not covered by existing Splunk saved searches
                and get recommended detection SPL.
              </p>
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
            <div className="mt-4 py-8 flex flex-col items-center gap-3">
              <div className="w-6 h-6 border-2 border-sentinel-accent border-t-transparent
                              rounded-full animate-spin" />
              <p className="text-xs text-sentinel-muted">
                Checking {gaps?.techniques_analyzed || ''} MITRE techniques against Splunk saved searches…
              </p>
            </div>
          )}

          {/* Results */}
          {gaps && !loading && (
            <>
              {/* Summary row */}
              <div className="mt-4 grid grid-cols-4 gap-3">
                {[
                  { label: 'Techniques Analyzed', value: gaps.techniques_analyzed },
                  { label: 'Covered', value: gaps.covered, color: 'text-green-400' },
                  { label: 'Gaps Found', value: gaps.not_covered, color: 'text-red-400' },
                  { label: 'Saved Searches Checked', value: gaps.saved_searches_checked ?? '—' },
                ].map(({ label, value, color }) => (
                  <div key={label}
                       className="border border-sentinel-border rounded-xl p-3 bg-sentinel-bg">
                    <p className="text-[10px] text-sentinel-muted uppercase tracking-wider mb-1">{label}</p>
                    <p className={`text-xl font-bold font-mono ${color || 'text-white'}`}>{value}</p>
                  </div>
                ))}
              </div>

              {/* Gaps */}
              {gaps.gaps && gaps.gaps.length > 0 && (
                <div>
                  <p className="text-xs font-semibold text-red-400 uppercase tracking-wider mb-3">
                    Uncovered Techniques — {gaps.gaps.length} Gap{gaps.gaps.length !== 1 ? 's' : ''}
                  </p>
                  <div className="space-y-3">
                    {gaps.gaps.map(gap => (
                      <div key={gap.technique_id}
                           className="border border-red-500/20 rounded-xl bg-red-500/5">
                        {/* Gap header */}
                        <div
                          className="flex items-center justify-between px-4 py-3
                                     cursor-pointer hover:bg-red-500/10 transition-colors rounded-xl"
                          onClick={() => toggleGap(gap.technique_id)}
                        >
                          <div className="flex items-center gap-3">
                            <span className="text-[10px] font-bold text-red-400 uppercase">GAP</span>
                            <span className="text-xs font-mono font-bold text-sentinel-accent">
                              {gap.technique_id}
                            </span>
                            <span className="text-xs text-white">{gap.technique_name}</span>
                            <span className="text-xs text-sentinel-muted">· {gap.tactic}</span>
                          </div>
                          <span className="text-sentinel-muted text-xs">
                            {expandedGaps[gap.technique_id] ? '▲' : '▼'}
                          </span>
                        </div>

                        {/* Gap SPL */}
                        {expandedGaps[gap.technique_id] && gap.recommended_spl && (
                          <div className="px-4 pb-4">
                            <div className="flex items-center justify-between mb-2">
                              <span className="text-[10px] text-sentinel-muted font-mono">
                                RECOMMENDED SPL ({gap.generation_method})
                              </span>
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
                                    ? 'Deploying…'
                                    : deployed[gap.technique_id]?.success
                                      ? 'Deployed ✓'
                                      : 'Deploy as Saved Search'}
                                </button>
                              </div>
                            </div>

                            <pre className="bg-sentinel-bg border border-sentinel-border
                                           rounded-lg p-3 text-xs font-mono text-sentinel-accent
                                           overflow-x-auto whitespace-pre-wrap break-all">
                              {gap.recommended_spl}
                            </pre>

                            {deployed[gap.technique_id] && (
                              <div className="mt-2 text-[11px]">
                                {deployed[gap.technique_id].success ? (
                                  <span className="text-green-400">
                                    ✓ {deployed[gap.technique_id].message || 'Successfully deployed!'}
                                  </span>
                                ) : (
                                  <span className="text-red-400">
                                    ⚠ Error: {deployed[gap.technique_id].error}
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
                          <span className="text-xs font-bold text-green-400">✓ COVERED</span>
                          <span className="text-xs font-mono text-sentinel-accent">
                            {tech.technique_id}
                          </span>
                          <span className="text-xs text-white">{tech.technique_name}</span>
                          <span className="text-xs text-sentinel-muted">· {tech.tactic}</span>
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
  const confidenceLabel =
    report.confidence?.primary_label || 'Evidence Confidence'

  const handleEnrichmentComplete = (enrichedMappings) => {
    setEnrichedTtpMappings(enrichedMappings)
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
              {Math.round(primaryConfidence * 100)}%
            </div>
            <div className="text-[10px] text-sentinel-muted uppercase tracking-widest mt-1">{confidenceLabel}</div>
            
            {/* SLO Status Pill */}
            {report.slo_report && (
              <div className="mt-4 flex justify-end group/slo relative">
                <div 
                  className={`flex items-center gap-1.5 px-2 py-0.5 rounded-full border cursor-help transition-all
                    ${report.slo_report.overall_slo_status === 'ALL_MET' 
                      ? 'bg-green-500/5 border-green-500/20 text-green-400/80 hover:border-green-500/40' 
                      : 'bg-red-500/5 border-red-500/20 text-red-400/80 hover:border-red-500/40'
                    }`}
                  title="System Performance Compliance"
                >
                  <Zap className={`w-2.5 h-2.5 ${
                    report.slo_report.overall_slo_status === 'ALL_MET' ? 'text-green-400' : 'text-red-400'
                  }`} />
                  <span className="text-[10px] font-bold font-mono tracking-tight">
                    SLO: {report.slo_report.overall_slo_status === 'ALL_MET' ? 'PASS' : 'BREACH'}
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

      {/* Report sections */}
      <div className="space-y-6">
        <ExecutiveSummary report={report} />

        <ConfidenceBreakdownPanel investigationId={reportInvestigationId} />
        
        <FindingsGrid findings={report.key_findings || []} />

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <RecommendedActions actions={report.recommended_actions || []} />
          <CveList cves={report.cves_identified || []} />
        </div>

        <ContainmentPlanPanel 
          investigationId={reportInvestigationId}
          plan={report.containment_plan}
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

        <MltkEnrichmentStatus
          investigationId={reportInvestigationId}
          onEnrichmentComplete={handleEnrichmentComplete}
        />

        <MitreTable
          techniques={report.mitre_techniques_used || []}
          ttpMappings={ttpData}
        />

        <DetectionGapPanel
          investigationId={reportInvestigationId}
        />
        
        <ThreatIntelCards threatIntel={activeResult?.threat_intel || {}} />
        
        {/* Counterfactual Reasoning */}
        {report?.counterfactual_reasoning && (
          <CounterfactualCard
            counterfactual={report.counterfactual_reasoning}
            confirmedClassification={report.classification}
          />
        )}

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
