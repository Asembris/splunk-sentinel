export default function FindingsGrid({ findings }) {
  const confidenceColor = (c) => {
    if (c >= 0.8) return 'text-sentinel-success'
    if (c >= 0.6) return 'text-sentinel-warning'
    return 'text-sentinel-danger'
  }

  return (
    <div className="bg-sentinel-surface border border-sentinel-border rounded-xl p-6 shadow-lg">
      <h2 className="text-xs font-semibold text-sentinel-muted uppercase tracking-[0.1em] mb-4">
        Key Findings ({findings.length})
      </h2>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {findings.map((f, i) => (
          <div key={i} className="flex gap-4 p-4 bg-sentinel-bg rounded-xl border border-sentinel-border hover:border-sentinel-accent/50 transition-colors group">
            <div className="flex-shrink-0 text-center min-w-[50px] border-r border-sentinel-border pr-4">
              <span className={`text-xl font-bold tabular-nums ${confidenceColor(f.confidence)}`}>
                {Math.round(f.confidence * 100)}<span className="text-[10px] ml-0.5">%</span>
              </span>
              <div className="text-[9px] text-sentinel-muted uppercase tracking-tighter mt-1">{f.source}</div>
            </div>
            <div className="min-w-0">
              <p className="text-sm text-white font-medium leading-snug group-hover:text-sentinel-accent transition-colors">{f.finding}</p>
              <p className="text-[11px] text-sentinel-muted mt-2 leading-relaxed line-clamp-3 font-mono">{f.evidence}</p>
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}
