const TECHNIQUE_TACTIC_MAP = {
  T1190: 'Initial Access',
  T1078: 'Initial Access',
  T1566: 'Initial Access',
  T1059: 'Execution',
  T1047: 'Execution',
  T1053: 'Execution',
  T1543: 'Persistence',
  T1547: 'Persistence',
  T1548: 'Privilege Escalation',
  T1055: 'Privilege Escalation',
  T1027: 'Defense Evasion',
  T1070: 'Defense Evasion',
  T1562: 'Defense Evasion',
  T1110: 'Credential Access',
  T1528: 'Credential Access',
  T1552: 'Credential Access',
  T1087: 'Discovery',
  T1082: 'Discovery',
  T1083: 'Discovery',
  T1021: 'Lateral Movement',
  T1570: 'Lateral Movement',
  T1041: 'Exfiltration',
  T1567: 'Exfiltration',
  T1486: 'Impact',
  T1490: 'Impact',
  T1489: 'Impact',
  T1071: 'Command and Control',
  T1095: 'Command and Control',
}

const TACTIC_STYLE_MAP = {
  'Initial Access': { border: 'border-l-red-500', text: 'text-red-400', badge: 'bg-red-900/30 text-red-300 border-red-500/30' },
  'Execution': { border: 'border-l-blue-500', text: 'text-blue-400', badge: 'bg-blue-900/30 text-blue-300 border-blue-500/30' },
  'Persistence': { border: 'border-l-purple-500', text: 'text-purple-400', badge: 'bg-purple-900/30 text-purple-300 border-purple-500/30' },
  'Privilege Escalation': { border: 'border-l-orange-500', text: 'text-orange-400', badge: 'bg-orange-900/30 text-orange-300 border-orange-500/30' },
  'Defense Evasion': { border: 'border-l-slate-400', text: 'text-slate-400', badge: 'bg-slate-800/50 text-slate-300 border-slate-500/30' },
  'Credential Access': { border: 'border-l-amber-500', text: 'text-amber-400', badge: 'bg-amber-900/30 text-amber-300 border-amber-500/30' },
  'Discovery': { border: 'border-l-teal-500', text: 'text-teal-400', badge: 'bg-teal-900/30 text-teal-300 border-teal-500/30' },
  'Lateral Movement': { border: 'border-l-orange-400', text: 'text-orange-400', badge: 'bg-orange-900/30 text-orange-300 border-orange-500/30' },
  'Exfiltration': { border: 'border-l-rose-500', text: 'text-rose-400', badge: 'bg-rose-900/30 text-rose-300 border-rose-500/30' },
  'Impact': { border: 'border-l-red-600', text: 'text-red-400', badge: 'bg-red-900/40 text-red-200 border-red-600/30' },
  'Command and Control': { border: 'border-l-violet-500', text: 'text-violet-400', badge: 'bg-violet-900/30 text-violet-300 border-violet-500/30' },
  'Unknown': { border: 'border-l-blue-500', text: 'text-blue-400', badge: 'bg-blue-900/30 text-blue-300 border-blue-500/30' },
}

export default function MitreTable({ techniques, ttpMappings }) {
  const enriched = techniques.map(t => {
    // Extract clean ID: "T1190 - Exploit..." -> "T1190"
    const cleanId = t.split(/[\s-]/)[0].trim()
    const mapping = ttpMappings.find(m =>
      m.technique_id === cleanId ||
      m.technique_id?.startsWith(cleanId) ||
      cleanId.startsWith(m.technique_id)
    )
    const baseId = cleanId.split('.')[0]
    const tactic = TECHNIQUE_TACTIC_MAP[baseId] || 'Unknown'
    const tacticStyle = TACTIC_STYLE_MAP[tactic] || TACTIC_STYLE_MAP['Unknown']
    const confidencePct = mapping?.confidence != null ? Math.round(mapping.confidence * 100) : null
    const mltkValidationRun = mapping?.mltk_validation_run === true
    const mltkAgrees = mapping?.mltk_agrees
    let validationLabel = 'NOT RUN'
    let validationTone = 'muted'
    if (mltkValidationRun) {
      if (mltkAgrees === true) {
        validationLabel = 'MLTK CONF'
        validationTone = 'success'
      }
      if (mltkAgrees === false) {
        validationLabel = 'MLTK REVIEW'
        validationTone = 'warning'
      }
    }
    const cveChips = (mapping?.cves || []).map(c => ({ id: c.cve_id || c, label: c.cve_id || c }))
    const hasDetection = !!(mapping?.detection_guidance && mapping.detection_guidance.trim().length > 0 && !mapping.detection_guidance.toLowerCase().includes('no specific') && !mapping.detection_guidance.toLowerCase().includes('no rag'))
    const hasMitigation = !!(mapping?.mitigations && mapping.mitigations.trim().length > 0)
    return {
      raw: t,
      id: cleanId,
      name: mapping?.technique_name || (t.includes(' - ') ? t.split(' - ')[1] : cleanId),
      tactic,
      tacticStyle,
      detection: mapping?.detection_guidance || null,
      mitigation: mapping?.mitigations || null,
      confidence: mapping?.confidence || null,
      confidencePct,
      cves: mapping?.cves || [],
      cveChips,
      mltkValidationRun: mapping?.mltk_validation_run === true,
      mltkAgrees: mapping?.mltk_agrees,
      mltkAlternative: mapping?.mltk_alternative || null,
      validationLabel,
      validationTone,
      hasDetection,
      hasMitigation,
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
                  <div className="font-medium text-white text-sm flex items-center gap-2 flex-wrap">
                    <span>{t.name}</span>
                    {t.mltkValidationRun && (
                      <span
                        className={`text-xs px-1.5 py-0.5 rounded border ${
                          t.mltkAgrees
                            ? 'text-green-400 border-green-500/30'
                            : 'text-amber-400 border-amber-500/30'
                        }`}
                      >
                        {t.mltkAgrees ? 'MLTK OK' : 'MLTK !'}
                      </span>
                    )}
                  </div>
                  {t.mltkAgrees === false && t.mltkAlternative && (
                    <div className="text-xs text-amber-400/70 mt-0.5">
                      MLTK suggests: {t.mltkAlternative}
                    </div>
                  )}
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
                  ) : '-'}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
