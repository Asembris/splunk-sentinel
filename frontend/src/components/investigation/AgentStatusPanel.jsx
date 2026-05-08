import { useInvestigation } from '../../store/InvestigationContext'
import { CheckCircle, Circle, Loader, AlertCircle } from 'lucide-react'

const AGENTS = [
  { key: 'triage_agent', label: 'Triage Agent', description: 'Classification & telemetry' },
  { key: 'reconstruction_agent', label: 'Reconstruction Agent', description: 'ReAct kill chain loop' },
  { key: 'threat_intel_agent', label: 'Threat Intel', description: 'VirusTotal · AbuseIPDB' },
  { key: 'ttp_agent', label: 'TTP Agent', description: 'MITRE ATT&CK RAG' },
  { key: 'synthesis_agent', label: 'Synthesis Agent', description: 'Report generation' },
]

const AGENT_MODES = {
  triage_agent:         { mode: 'FAST', icon: '⚡', color: 'text-amber-400' },
  reconstruction_agent: { mode: 'DEEP', icon: '🔍', color: 'text-blue-400' },
  threat_intel_agent:   { mode: 'FAST', icon: '⚡', color: 'text-amber-400' },
  ttp_agent:            { mode: 'FAST', icon: '⚡', color: 'text-amber-400' },
  synthesis_agent:      { mode: 'DEEP', icon: '🔍', color: 'text-blue-400' },
}

const STATUS_CONFIG = {
  waiting:  { icon: Circle,      color: 'text-sentinel-muted',   bg: 'bg-sentinel-border' },
  running:  { icon: Loader,      color: 'text-sentinel-accent',  bg: 'bg-blue-900/30' },
  complete: { icon: CheckCircle, color: 'text-sentinel-success', bg: 'bg-green-900/20' },
  error:    { icon: AlertCircle, color: 'text-sentinel-danger',  bg: 'bg-red-900/20' },
}

export default function AgentStatusPanel() {
  const { state } = useInvestigation()

  // Derive classification and severity from result or running state
  const classification = state.result?.attack_classification || ''

  return (
    <div className="bg-sentinel-surface border border-sentinel-border rounded-xl p-4 h-full shadow-lg">
      <h3 className="text-sm font-semibold text-sentinel-muted uppercase tracking-wider mb-4">
        Agent Pipeline
      </h3>
      <div className="space-y-2">
        {AGENTS.map(({ key, label, description }) => {
          const status = state.agentStatuses[key] || 'waiting'
          const { icon: Icon, color, bg } = STATUS_CONFIG[status]
          const isRunning = status === 'running'

          return (
            <div
              key={key}
              className={`flex items-center gap-3 p-3 rounded-lg transition-all relative group ${bg} ${
                status !== 'waiting' ? 'animate-fade-in' : ''
              }`}
            >
              <Icon
                className={`w-4 h-4 flex-shrink-0 ${color} ${
                  isRunning ? 'animate-spin' : ''
                }`}
              />
              <div className="min-w-0 flex-1 pr-12">
                <div className={`text-sm font-medium truncate ${
                  status === 'waiting' ? 'text-sentinel-muted' : 'text-white'
                }`}>
                  {label}
                </div>
                <div className="text-xs text-sentinel-muted truncate">
                  {description}
                </div>
              </div>

              {/* Mode Badge - Absolute Positioned */}
              {AGENT_MODES[key] && (
                <div className={`absolute top-2 right-2 text-[9px] font-bold flex items-center gap-1 px-1.5 py-0.5 rounded-md bg-sentinel-surface/80 backdrop-blur-sm border border-sentinel-border/50 shadow-sm ${AGENT_MODES[key].color}`}>
                  {AGENT_MODES[key].icon} {AGENT_MODES[key].mode}
                </div>
              )}

              {/* Triage Classification */}
              {status === 'complete' && key === 'triage_agent' && classification && (
                <span className="absolute bottom-2 right-2 text-[9px] font-mono text-sentinel-accent border border-blue-900/50 px-1 py-0.5 rounded uppercase bg-blue-900/10">
                  {classification}
                </span>
              )}
            </div>
          )
        })}
      </div>

      {/* Confidence */}
      <div className="mt-6 pt-4 border-t border-sentinel-border">
        <div className="flex justify-between items-center mb-2">
          <span className="text-xs text-sentinel-muted">Pipeline Confidence</span>
          <span className="text-sm font-bold text-sentinel-accent">
            {(state.confidence * 100).toFixed(0)}%
          </span>
        </div>
        <div className="h-2 bg-sentinel-border rounded-full overflow-hidden">
          <div
            className="h-full bg-sentinel-accent rounded-full transition-all duration-1000"
            style={{ width: `${state.confidence * 100}%` }}
          />
        </div>
      </div>

      {/* Iteration counter */}
      {state.currentIteration > 0 && (
        <div className="mt-3 text-[10px] text-sentinel-muted text-center uppercase tracking-tighter">
          ReAct iteration {state.currentIteration} / {state.totalIterations}
        </div>
      )}
    </div>
  )
}
