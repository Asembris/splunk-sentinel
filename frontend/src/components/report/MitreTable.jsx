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
    <div className="bg-sentinel-surface border border-sentinel-border rounded-xl p-6" style={{ borderTop: '2px solid #3b82f6' }}>
      <div className="flex flex-col gap-2 mb-5">
        <div className="flex flex-row items-start justify-between gap-3">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <div className="w-2 h-4 rounded-sm bg-sentinel-accent" />
              <h3 className="text-sm font-bold text-white tracking-wide">
                MITRE ATT&CK Technique Validation
              </h3>
            </div>
            <p className="text-xs text-sentinel-muted ml-4">
              {enriched.length} technique{enriched.length !== 1 ? 's' : ''} mapped
              {(() => {
                const validated = enriched.filter(t => t.mltkValidationRun).length
                const agreements = enriched.filter(t => t.mltkValidationRun && t.mltkAgrees === true).length
                const disagreements = enriched.filter(t => t.mltkValidationRun && t.mltkAgrees === false).length
                if (validated === 0) return null
                return (
                  <>
                    <span className="text-sentinel-muted"> &bull; </span>
                    <span className="text-green-400">{validated} MLTK validated</span>
                    {agreements > 0 && (
                      <>
                        <span className="text-sentinel-muted"> &bull; </span>
                        <span className="text-green-400">{agreements} agreement{agreements !== 1 ? 's' : ''}</span>
                      </>
                    )}
                    {disagreements > 0 && (
                      <>
                        <span className="text-sentinel-muted"> &bull; </span>
                        <span className="text-amber-400">{disagreements} disagreement{disagreements !== 1 ? 's' : ''}</span>
                      </>
                    )}
                  </>
                )
              })()}
            </p>
          </div>
          <div className="flex items-center gap-2 flex-wrap shrink-0">
            <span className="text-xs px-2 py-1 rounded bg-sentinel-bg border border-sentinel-border text-sentinel-muted whitespace-nowrap">
              QDRANT RAG
            </span>
            <span className="text-xs px-2 py-1 rounded bg-sentinel-bg border border-sentinel-border text-sentinel-muted whitespace-nowrap">
              MLTK AI
            </span>
            <span className="text-xs px-2 py-1 rounded bg-sentinel-bg border border-sentinel-border text-sentinel-muted whitespace-nowrap">
              ATT&CK
            </span>
          </div>
        </div>
      </div>
      {enriched.length === 0 ? (
        <div className="py-8 text-center text-xs text-sentinel-muted">
          No MITRE techniques mapped for this investigation.
        </div>
      ) : (
        <div className="flex flex-col gap-3">
          {enriched.map((t, i) => (
            <div
              key={i}
              className={`bg-sentinel-bg border border-sentinel-border rounded-lg border-l-4 ${t.tacticStyle.border} p-4`}
            >
              <div className="flex flex-col sm:flex-row sm:items-start sm:justify-between gap-4">
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap mb-1">
                    <a
                      href={`https://attack.mitre.org/techniques/${t.id.replace('.', '/')}/`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="font-mono text-xs px-1.5 py-0.5 rounded border border-sentinel-border bg-sentinel-surface text-sentinel-accent hover:border-sentinel-accent transition-colors"
                    >
                      {t.id}
                    </a>
                    <span className={`text-xs font-bold uppercase tracking-wider px-1.5 py-0.5 rounded border ${t.tacticStyle.badge}`}>
                      {t.tactic}
                    </span>
                  </div>
                  <p className="text-sm font-semibold text-white leading-tight mb-2">
                    {t.name}
                  </p>
                  {t.cveChips.length > 0 && (
                    <div className="flex gap-1.5 flex-wrap">
                      {t.cveChips.slice(0, 2).map(c => (
                        <span
                          key={c.id}
                          className="text-xs font-mono px-1.5 py-0.5 rounded border border-amber-500/30 bg-amber-900/20 text-amber-300"
                        >
                          {c.label}
                        </span>
                      ))}
                      {t.cveChips.length > 2 && (
                        <span className="text-xs font-mono px-1.5 py-0.5 rounded border border-sentinel-border bg-sentinel-surface text-sentinel-muted">
                          +{t.cveChips.length - 2}
                        </span>
                      )}
                    </div>
                  )}
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
