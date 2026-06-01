import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useInvestigation } from '../store/InvestigationContext'
import { Shield, Zap, AlertTriangle, User } from 'lucide-react'
import BrandLogo from '../components/layout/BrandLogo'

const EXAMPLE_TRIGGERS = [
  {
    icon: Zap,
    label: 'APT / SSRF',
    color: 'text-sentinel-danger',
    trigger: 'Suspicious outbound requests to AWS metadata endpoint detected from internal web server. Possible SSRF attack leading to IAM credential exposure.',
  },
  {
    icon: AlertTriangle,
    label: 'Ransomware',
    color: 'text-sentinel-warning',
    trigger: 'High volume of WMIC and cmd.exe process creation detected from non-interactive sessions. Registry modification activity observed across multiple internal hosts.',
  },
  {
    icon: User,
    label: 'Insider Threat',
    color: 'text-sentinel-success',
    trigger: 'Privileged service abuse detected. Multiple EventCode 4673 entries from single internal account outside business hours. No external communication observed.',
  },
]

const PIPELINE_AGENTS = [
  {
    name: 'Triage',
    description: 'Classifies attack type across APT, ransomware, and insider threat',
    dotClass: 'w-2 h-2 rounded-full bg-red-400 animate-pulse',
  },
  {
    name: 'Reconstruction',
    description: 'Rebuilds attack sequence from 2M+ Splunk log events',
    dotClass: 'w-2 h-2 rounded-full bg-blue-400 animate-pulse',
  },
  {
    name: 'Threat Intel',
    description: 'Correlates IPs and CVEs against live threat intelligence',
    dotClass: 'w-2 h-2 rounded-full bg-amber-400 animate-pulse',
  },
  {
    name: 'MITRE Mapping',
    description: 'Maps evidence to 697 ATT&CK techniques via RAG',
    dotClass: 'w-2 h-2 rounded-full bg-purple-400 animate-pulse',
  },
  {
    name: 'Detection Gap',
    description: 'Finds uncovered techniques and generates deployment-ready SPL',
    dotClass: 'w-2 h-2 rounded-full bg-teal-400 animate-pulse',
  },
  {
    name: 'Report',
    description: 'Produces analyst-ready PDF with containment and audit trail',
    dotClass: 'w-2 h-2 rounded-full bg-green-400 animate-pulse',
  },
]

export default function InvestigatePage() {
  const [trigger, setTrigger] = useState('')
  const [loading, setLoading] = useState(false)
  const { startInvestigation } = useInvestigation()
  const navigate = useNavigate()

  const handleSubmit = async () => {
    if (!trigger.trim() || loading) return
    setLoading(true)
    navigate('/dashboard')
    await startInvestigation(trigger.trim())
    setLoading(false)
  }

  return (
    <div className="min-h-[calc(100vh-57px)] flex flex-col items-center justify-center px-6 py-12">
      {/* Hero */}
      <div className="text-center mb-12 animate-fade-in">
        <div className="flex items-center justify-center gap-3 mb-4">
          <BrandLogo variant="mark" className="h-16 w-16" />
        </div>
        <h1 className="text-4xl font-bold mb-3 text-white">
          Autonomous SOC Investigation
        </h1>
        <p className="text-sentinel-muted text-lg max-w-2xl">
          Describe a security alert. Sentinel reconstructs the full attack 
          kill chain from 2M+ log events in ~100 seconds.
        </p>
      </div>

      {/* Investigation work zone */}
      <div className="w-full max-w-6xl mx-auto animate-fade-in" style={{ animationDelay: '0.1s' }}>
        <div className="grid grid-cols-1 lg:grid-cols-[1.2fr_0.8fr] gap-8">
          <div
            className="bg-sentinel-surface border border-sentinel-border rounded-xl p-6 shadow-xl"
            style={{ borderTop: '2px solid #3b82f6' }}
          >
            <div className="flex items-start justify-between gap-4 mb-4">
              <div>
                <div className="flex items-center gap-2 mb-1">
                  <div className="w-2 h-4 rounded-sm bg-sentinel-accent" />
                  <label className="text-sm font-bold text-white tracking-wide">
                    Security Alert Intake
                  </label>
                </div>
                <p className="text-xs text-sentinel-muted ml-4">
                  Paste raw alert context, detection notes, or incident telemetry.
                </p>
              </div>
              <span className="text-xs px-2 py-1 rounded border border-sentinel-border bg-sentinel-bg text-sentinel-muted whitespace-nowrap">
                Ctrl+Enter
              </span>
            </div>
            <textarea
              value={trigger}
              onChange={e => setTrigger(e.target.value)}
              placeholder="Describe the security alert or incident trigger..."
              className="w-full bg-sentinel-bg border border-sentinel-border rounded-lg p-4 text-white placeholder-sentinel-muted resize-none focus:outline-none focus:border-sentinel-accent transition-colors text-sm leading-relaxed"
              rows={4}
              onKeyDown={e => {
                if (e.key === 'Enter' && (e.metaKey || e.ctrlKey)) handleSubmit()
              }}
            />
            <div className="flex items-center justify-between mt-4">
              <span className="text-xs text-sentinel-muted">
                Raw alert will be routed through autonomous triage.
              </span>
              <button
                onClick={handleSubmit}
                disabled={!trigger.trim() || loading}
                className="flex items-center gap-2 px-6 py-2.5 bg-sentinel-accent hover:bg-blue-500 disabled:opacity-50 disabled:cursor-not-allowed text-white font-medium rounded-lg transition-all transform active:scale-95 text-sm"
              >
                <Shield className="w-4 h-4" />
                {loading ? 'Launching...' : 'Launch Investigation'}
              </button>
            </div>
          </div>

          <div className="bg-sentinel-surface border border-sentinel-border rounded-xl p-6 shadow-xl h-full">
            <div className="flex items-start justify-between gap-4 mb-5">
              <div>
                <div className="flex items-center gap-2 mb-1">
                  <div className="w-2 h-4 rounded-sm bg-sentinel-accent" />
                  <h2 className="text-sm font-bold text-white tracking-wide">
                    Autonomous Pipeline
                  </h2>
                </div>
                <p className="text-xs text-sentinel-muted ml-4">
                  Six-agent investigation architecture.
                </p>
              </div>
              <span className="text-xs px-2 py-1 rounded border border-sentinel-border bg-sentinel-bg text-sentinel-muted whitespace-nowrap">
                6 Agents
              </span>
            </div>
            <div className="relative">
              <div className="absolute left-[9px] top-3 bottom-3 w-px bg-blue-500/30" />
              <div className="space-y-4">
                {PIPELINE_AGENTS.map(agent => (
                  <div key={agent.name} className="relative flex gap-3">
                    <div className="relative z-10 flex h-5 w-5 items-center justify-center rounded-full border border-sentinel-border bg-sentinel-bg shrink-0">
                      <span className={agent.dotClass} />
                    </div>
                    <div className="min-w-0 flex-1">
                      <h3 className="text-sm font-semibold text-white leading-tight">
                        {agent.name}
                      </h3>
                      <p className="text-xs text-sentinel-muted leading-relaxed mt-0.5">
                        {agent.description}
                      </p>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>

        {/* Example triggers */}
        <div className="grid grid-cols-3 gap-3 mt-4 max-w-3xl mx-auto">
          {EXAMPLE_TRIGGERS.map(({ icon: Icon, label, color, trigger: t }) => (
            <button
              key={label}
              onClick={() => setTrigger(t)}
              className="flex items-center gap-2 p-3 bg-sentinel-surface border border-sentinel-border hover:border-sentinel-accent rounded-lg text-left transition-colors group"
            >
              <Icon className={`w-4 h-4 ${color} flex-shrink-0`} />
              <span className="text-sm text-sentinel-muted group-hover:text-white transition-colors">
                {label}
              </span>
            </button>
          ))}
        </div>
      </div>

      {/* Stats footer */}
      <div className="flex items-center gap-8 mt-16 text-center animate-fade-in" style={{ animationDelay: '0.2s' }}>
        {[
          { value: '2M+', label: 'Log Events Analyzed' },
          { value: '697', label: 'MITRE Techniques' },
          { value: '~100', label: 'Investigation Time' },
          { value: '6', label: 'AI Agents' },
        ].map(({ value, label }) => (
          <div key={label}>
            <div className="text-2xl font-bold text-sentinel-accent">{value}</div>
            <div className="text-xs text-sentinel-muted mt-1">{label}</div>
          </div>
        ))}
      </div>
    </div>
  )
}
