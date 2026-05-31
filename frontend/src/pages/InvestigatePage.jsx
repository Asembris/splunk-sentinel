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
          <BrandLogo variant="mark" className="h-14 w-14" />
        </div>
        <h1 className="text-4xl font-bold mb-3 text-white">
          Autonomous SOC Investigation
        </h1>
        <p className="text-sentinel-muted text-lg max-w-2xl">
          Describe a security alert. Sentinel reconstructs the full attack 
          kill chain from 2M+ log events in ~100 seconds.
        </p>
      </div>

      {/* Input */}
      <div className="w-full max-w-3xl animate-fade-in" style={{ animationDelay: '0.1s' }}>
        <div className="bg-sentinel-surface border border-sentinel-border rounded-xl p-6 mb-4 shadow-xl">
          <label className="block text-sm font-medium text-sentinel-muted mb-3">
            SECURITY ALERT TRIGGER
          </label>
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
              Press Ctrl+Enter to investigate
            </span>
            <button
              onClick={handleSubmit}
              disabled={!trigger.trim() || loading}
              className="flex items-center gap-2 px-6 py-2.5 bg-sentinel-accent hover:bg-blue-500 disabled:opacity-50 disabled:cursor-not-allowed text-white font-medium rounded-lg transition-all transform active:scale-95 text-sm"
            >
              <Shield className="w-4 h-4" />
              {loading ? 'Starting...' : 'Investigate'}
            </button>
          </div>
        </div>

        {/* Example triggers */}
        <div className="grid grid-cols-3 gap-3">
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
