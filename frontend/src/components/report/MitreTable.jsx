export default function MitreTable({ techniques, ttpMappings }) {
  const enriched = techniques.map(t => {
    const techId = t.split(' ')[0]
    const mapping = (ttpMappings || []).find(m => m.technique_id === techId)
    return { id: t, techId, ...mapping }
  })

  return (
    <div className="bg-sentinel-surface border border-sentinel-border rounded-xl p-6 shadow-lg">
      <h2 className="text-xs font-semibold text-sentinel-muted uppercase tracking-[0.1em] mb-4">
        MITRE ATT&CK Matrix Mapping
      </h2>
      <div className="overflow-x-auto">
        <table className="w-full text-sm border-collapse">
          <thead>
            <tr className="text-left text-[10px] text-sentinel-muted uppercase tracking-widest border-b border-sentinel-border">
              <th className="pb-3 pr-4 font-black">ID</th>
              <th className="pb-3 pr-4 font-black">Technique Name</th>
              <th className="pb-3 pr-4 font-black">Detection Guidance</th>
              <th className="pb-3 text-right font-black">Rel.</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-sentinel-border">
            {enriched.map((t, i) => (
              <tr key={i} className="text-white hover:bg-sentinel-bg/50 transition-colors group">
                <td className="py-4 pr-4 font-mono text-sentinel-accent text-xs">
                  {t.techId}
                </td>
                <td className="py-4 pr-4">
                  <div className="text-sm font-bold group-hover:text-sentinel-accent transition-colors">{t.technique_name || t.id.replace(t.techId, '').trim() || t.id}</div>
                  <div className="text-[10px] text-sentinel-muted mt-1 uppercase tracking-tight">{t.tactic_name || 'Standard Tactic'}</div>
                </td>
                <td className="py-4 pr-4 text-xs text-sentinel-muted max-w-sm">
                  <p className="leading-relaxed line-clamp-2">{t.detection_guidance || 'No specific detection guidance available in current dataset.'}</p>
                </td>
                <td className="py-4 text-right text-[11px] font-bold tabular-nums">
                  {t.confidence ? `${Math.round(t.confidence * 100)}%` : '—'}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
