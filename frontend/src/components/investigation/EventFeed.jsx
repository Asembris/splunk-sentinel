import { useEffect, useRef } from 'react'
import { useInvestigation } from '../../store/InvestigationContext'
import { Terminal, Shield, AlertTriangle, CheckCircle, Info } from 'lucide-react'

const EVENT_STYLES = {
  system:    { color: 'text-sentinel-muted', icon: Info },
  agent:     { color: 'text-sentinel-accent', icon: Terminal },
  iteration: { color: 'text-sentinel-warning', icon: AlertTriangle },
  stage:     { color: 'text-sentinel-success', icon: Shield },
  complete:  { color: 'text-sentinel-success', icon: CheckCircle },
  error:     { color: 'text-sentinel-danger', icon: AlertTriangle },
}

function formatTime(iso) {
  try {
    return new Date(iso).toLocaleTimeString('en-US', {
      hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit'
    })
  } catch (e) {
    return '--:--:--'
  }
}

const HUMAN_MESSAGES = {
  'Triage Agent started': 'Initializing triage: Scanning alerts and identifying priority vectors...',
  'Reconstruction Agent started': 'Tracing attack path: Reconstructing sequence of events...',
  'Threat Intel Agent started': 'Correlating intelligence: Querying global threat feeds...',
  'TTP Agent started': 'Analyzing behavior: Mapping observed actions to MITRE techniques...',
  'Synthesis Agent started': 'Finalizing analysis: Compiling forensic evidence into summary...',
}

export default function EventFeed() {
  const { state } = useInvestigation()
  const bottomRef = useRef(null)

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [state.events])

  return (
    <div className="bg-sentinel-surface border border-sentinel-border rounded-xl overflow-hidden shadow-lg flex flex-col" style={{ height: '460px' }}>
      <div className="px-4 py-3 border-b border-sentinel-border flex items-center justify-between">
        <h3 className="text-sm font-semibold text-sentinel-muted uppercase tracking-wider">
          Forensic Event Feed
        </h3>
        <div className="flex gap-1">
          <div className="w-1.5 h-1.5 rounded-full bg-red-500 animate-pulse" />
          <div className="w-1.5 h-1.5 rounded-full bg-sentinel-border" />
          <div className="w-1.5 h-1.5 rounded-full bg-sentinel-border" />
        </div>
      </div>
      <div className="flex-1 overflow-y-auto p-4 space-y-3 scroll-smooth scrollbar-thin scrollbar-thumb-sentinel-border">
        {state.events.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-full opacity-20">
            <Terminal className="w-8 h-8 mb-2" />
            <p className="text-xs italic font-mono">Listening for pipeline events...</p>
          </div>
        ) : (
          state.events.map((event, i) => {
            const config = EVENT_STYLES[event.type] || { color: 'text-white', icon: Info }
            const Icon = config.icon
            const message = HUMAN_MESSAGES[event.message] || event.message

            return (
              <div key={i} className="flex gap-3 animate-fade-in group items-start">
                <div className={`mt-0.5 p-1 rounded bg-gray-800/50 ${config.color}`}>
                  <Icon className="w-3 h-3" />
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-0.5">
                    <span className="text-[10px] text-sentinel-muted font-mono">
                      {formatTime(event.time)}
                    </span>
                    <span className={`text-[9px] uppercase tracking-tighter px-1 rounded bg-opacity-10 border border-opacity-20 ${config.color} ${config.color.replace('text-', 'bg-').replace('text-', 'border-')}`}>
                      {event.type}
                    </span>
                  </div>
                  <p className={`text-[11px] leading-relaxed break-words font-medium ${
                    event.type === 'stage' ? 'text-white' : 'text-gray-300'
                  }`}>
                    {message}
                  </p>
                </div>
              </div>
            )
          })
        )}
        <div ref={bottomRef} className="h-2" />
      </div>
    </div>
  )
}
