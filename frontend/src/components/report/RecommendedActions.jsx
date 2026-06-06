const PRIORITY_CONFIG = {
  IMMEDIATE: {
    label: 'Immediate',
    border: 'border-l-red-500',
    badge: 'bg-red-900/30 text-red-300 border-red-500/30',
    dot: 'bg-red-400',
    text: 'text-red-400',
    empty: 'No immediate advisory action generated yet.',
    helper: 'Review after triage confirms the active threat path.',
  },
  SHORT_TERM: {
    label: 'Short Term',
    border: 'border-l-amber-500',
    badge: 'bg-amber-900/30 text-amber-300 border-amber-500/30',
    dot: 'bg-amber-400',
    text: 'text-amber-400',
    empty: 'No short-term recovery guidance generated yet.',
    helper: 'Review after containment actions are complete.',
  },
  LONG_TERM: {
    label: 'Long Term',
    border: 'border-l-emerald-500',
    badge: 'bg-emerald-900/30 text-emerald-300 border-emerald-500/30',
    dot: 'bg-emerald-400',
    text: 'text-emerald-400',
    empty: 'No long-term hardening action generated yet.',
    helper: 'Review after containment and recovery are complete.',
  },
}

const PRIORITY_ORDER = ['IMMEDIATE', 'SHORT_TERM', 'LONG_TERM']

export default function RecommendedActions({ actions }) {
  const grouped = actions.reduce((acc, a) => {
    const p = a.priority || 'SHORT_TERM'
    if (!acc[p]) acc[p] = []
    acc[p].push(a)
    return acc
  }, {})

  return (
    <div
      className="bg-sentinel-surface border border-sentinel-border rounded-xl p-6 shadow-lg"
      style={{ borderTop: '2px solid #3b82f6' }}
    >
      <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between mb-4">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <div className="w-2 h-4 rounded-sm bg-sentinel-accent" />
            <h2 className="text-sm font-bold text-white tracking-wide">
              Strategic Remediation Plan
            </h2>
          </div>
          <p className="text-xs text-sentinel-muted ml-4">
            Prioritized containment, recovery, and hardening recommendations
          </p>
        </div>
        <span className="text-xs px-2 py-1 rounded bg-sentinel-bg border border-sentinel-border text-sentinel-muted whitespace-nowrap">
          3 phases
        </span>
      </div>
      <div className="flex flex-col gap-3">
        {PRIORITY_ORDER.map(priority => {
          const config = PRIORITY_CONFIG[priority]
          const items = grouped[priority] || []
          return (
            <div
              key={priority}
              className={`bg-sentinel-bg border border-sentinel-border border-l-4 ${config.border} rounded-lg p-4`}
            >
              <div className="flex flex-col gap-2 sm:flex-row sm:items-start sm:justify-between mb-3">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className={`text-xs font-bold px-2 py-1 rounded border ${config.badge}`}>
                    <span className={`inline-block w-1.5 h-1.5 rounded-full mr-1.5 ${config.dot}`} />
                    {config.label}
                  </span>
                  <span className="text-xs text-sentinel-muted">
                    {items.length} action{items.length !== 1 ? 's' : ''}
                  </span>
                </div>
                <span className={`text-[10px] font-bold uppercase tracking-wider ${config.text}`}>
                  {priority.replace('_', ' ')}
                </span>
              </div>
              {items.length === 0 ? (
                <div>
                  <p className="text-sm text-sentinel-muted italic">
                    {config.empty}
                  </p>
                  <p className="text-xs text-sentinel-muted/70 mt-1">
                    {config.helper}
                  </p>
                </div>
              ) : (
                <div>
                  {items.map((a, i) => (
                    <div
                      key={i}
                      className={i === 0 ? '' : 'border-t border-sentinel-border/40 pt-3 mt-3'}
                    >
                      <p className="text-sm text-white font-semibold leading-tight">
                        {a.action}
                      </p>
                      <p className="text-xs text-sentinel-muted mt-2 leading-relaxed">
                        {a.rationale}
                      </p>
                      {a.mitre_technique &&
                        a.mitre_technique !== 'N/A' &&
                        a.mitre_technique.trim().length > 0 && (
                        <div className="mt-2 flex items-center gap-1.5">
                          <span className="text-[9px] font-mono text-sentinel-accent bg-blue-900/20 px-1.5 py-0.5 rounded uppercase">
                            {a.mitre_technique}
                          </span>
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>
          )
        })}
      </div>
      <p className="text-xs text-sentinel-muted mt-3 pt-3 border-t border-sentinel-border/40">
        Advisory remediation guidance only. Actions shown here are not executed; executable containment actions are handled in the Containment Plan section.
      </p>
    </div>
  )
}
