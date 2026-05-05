const PRIORITY_CONFIG = {
  IMMEDIATE:   { color: 'border-sentinel-danger text-sentinel-danger',   bg: 'bg-red-900/10' },
  SHORT_TERM:  { color: 'border-sentinel-warning text-sentinel-warning', bg: 'bg-yellow-900/10' },
  LONG_TERM:   { color: 'border-sentinel-success text-sentinel-success', bg: 'bg-green-900/10' },
}

export default function RecommendedActions({ actions }) {
  const grouped = actions.reduce((acc, a) => {
    const p = a.priority || 'SHORT_TERM'
    if (!acc[p]) acc[p] = []
    acc[p].push(a)
    return acc
  }, {})

  return (
    <div className="bg-sentinel-surface border border-sentinel-border rounded-xl p-6 shadow-lg">
      <h2 className="text-xs font-semibold text-sentinel-muted uppercase tracking-[0.1em] mb-4">
        Strategic Remediation Plan
      </h2>
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {['IMMEDIATE', 'SHORT_TERM', 'LONG_TERM'].map(priority => {
          const { color, bg } = PRIORITY_CONFIG[priority]
          const items = grouped[priority] || []
          return (
            <div key={priority} className={`rounded-xl border p-4 shadow-inner ${bg} ${color.split(' ')[0]}`}>
              <div className={`text-[10px] font-black mb-4 uppercase tracking-[0.2em] flex items-center gap-2 ${color.split(' ')[1]}`}>
                <span className={`w-1.5 h-1.5 rounded-full bg-current`} />
                {priority.replace('_', ' ')}
              </div>
              {items.length === 0 ? (
                <p className="text-[10px] text-sentinel-muted uppercase tracking-wider italic">No actions defined</p>
              ) : (
                <div className="space-y-4">
                  {items.map((a, i) => (
                    <div key={i} className="group/action">
                      <p className="text-sm text-white font-semibold leading-tight">{a.action}</p>
                      <p className="text-[11px] text-sentinel-muted mt-2 leading-relaxed">{a.rationale}</p>
                      {a.mitre_technique && (
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
    </div>
  )
}
