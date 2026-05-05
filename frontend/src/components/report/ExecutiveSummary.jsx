export default function ExecutiveSummary({ report }) {
  return (
    <div className="bg-sentinel-surface border border-sentinel-border rounded-xl p-6 shadow-lg">
      <h2 className="text-xs font-semibold text-sentinel-muted uppercase tracking-[0.1em] mb-4">
        Executive Summary
      </h2>
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
