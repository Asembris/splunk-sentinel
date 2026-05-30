export default function ExecutiveSummary({ report }) {
  return (
    <div className="bg-sentinel-surface border border-sentinel-border rounded-xl p-6 shadow-lg" style={{ borderTop: '2px solid #3b82f6' }}>
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <div className="w-2 h-4 rounded-sm bg-sentinel-accent" />
          <h2 className="text-sm font-bold text-white tracking-wide">
            Executive Brief
          </h2>
        </div>
      </div>
      <p className="text-white text-sm leading-relaxed antialiased">{report.executive_summary}</p>
      {report.threat_actor_profile && (
        <div className="mt-5 pt-5 border-t border-sentinel-border/50">
          <h3 className="text-[10px] font-bold text-sentinel-accent uppercase tracking-wider mb-2">Threat Actor Profile</h3>
          <p className="text-xs text-sentinel-muted leading-relaxed italic">{report.threat_actor_profile}</p>
        </div>
      )}
    </div>
  )
}
