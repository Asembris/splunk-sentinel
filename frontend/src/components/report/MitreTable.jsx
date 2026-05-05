export default function MitreTable({ techniques, ttpMappings }) {
  const enriched = techniques.map(t => {
    // Extract clean ID: "T1190 - Exploit..." → "T1190"
    const cleanId = t.split(/[\s-]/)[0].trim()
    const mapping = ttpMappings.find(m =>
      m.technique_id === cleanId ||
      m.technique_id?.startsWith(cleanId) ||
      cleanId.startsWith(m.technique_id)
    )
    return {
      raw: t,
      id: cleanId,
      name: mapping?.technique_name || (t.includes(' - ') ? t.split(' - ')[1] : cleanId),
      detection: mapping?.detection_guidance || null,
      mitigation: mapping?.mitigations || null,
      confidence: mapping?.confidence || null,
      cves: mapping?.cves || [],
    }
  })

  return (
    <div className="bg-sentinel-surface border border-sentinel-border rounded-xl p-6">
      <h2 className="text-sm font-semibold text-sentinel-muted uppercase tracking-wider mb-4">
        MITRE ATT&CK Matrix Mapping
      </h2>
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="text-left text-xs text-sentinel-muted border-b border-sentinel-border">
              <th className="pb-3 pr-4 w-24">ID</th>
              <th className="pb-3 pr-4 w-48">Technique</th>
              <th className="pb-3 pr-4">Detection Guidance</th>
              <th className="pb-3 w-16 text-right">Score</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-sentinel-border">
            {enriched.map((t, i) => (
              <tr key={i} className="hover:bg-sentinel-bg transition-colors">
                <td className="py-3 pr-4">
                  <a
                    href={`https://attack.mitre.org/techniques/${t.id.replace('.', '/')}/`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="font-mono text-xs text-sentinel-accent hover:underline"
                  >
                    {t.id}
                  </a>
                </td>
                <td className="py-3 pr-4">
                  <div className="font-medium text-white text-sm">{t.name}</div>
                  {t.cves.length > 0 && (
                    <div className="flex gap-1 mt-1 flex-wrap">
                      {t.cves.slice(0, 2).map(c => (
                        <span key={c.cve_id} className="text-xs font-mono text-sentinel-warning">
                          {c.cve_id}
                        </span>
                      ))}
                    </div>
                  )}
                </td>
                <td className="py-3 pr-4">
                  {t.detection ? (
                    <p className="text-xs text-sentinel-muted leading-relaxed line-clamp-3">
                      {t.detection}
                    </p>
                  ) : (
                    <span className="text-xs text-sentinel-border italic">
                      No RAG data retrieved for this technique
                    </span>
                  )}
                </td>
                <td className="py-3 text-right">
                  {t.confidence ? (
                    <span className="text-xs font-bold text-sentinel-accent">
                      {Math.round(t.confidence * 100)}%
                    </span>
                  ) : '—'}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
