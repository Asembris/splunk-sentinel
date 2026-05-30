const CONFIDENCE_TONE_MAP = {
  high: {
    text: 'text-sentinel-success',
    border: 'border-green-500/30',
    bg: 'bg-green-500/10',
    bar: 'bg-green-500',
  },
  medium: {
    text: 'text-sentinel-warning',
    border: 'border-amber-500/30',
    bg: 'bg-amber-500/10',
    bar: 'bg-amber-500',
  },
  low: {
    text: 'text-sentinel-danger',
    border: 'border-red-500/30',
    bg: 'bg-red-500/10',
    bar: 'bg-red-500',
  },
  muted: {
    text: 'text-sentinel-muted',
    border: 'border-sentinel-border',
    bg: 'bg-sentinel-surface',
    bar: 'bg-sentinel-muted',
  },
}

const SOURCE_LABEL_MAP = {
  reconstructionagent: 'Reconstruction',
  triageagent: 'Triage',
  mitreagent: 'MITRE',
  reportagent: 'Report',
}

const normalizeConfidence = (value) => {
  const numeric = Number(value)
  if (!Number.isFinite(numeric)) {
    return {
      known: false,
      value: 0,
      display: '--',
    }
  }

  const clamped = Math.min(1, Math.max(0, numeric))
  return {
    known: true,
    value: clamped,
    display: Math.round(clamped * 100),
  }
}

const getConfidenceTone = (confidence) => {
  if (!confidence.known) return CONFIDENCE_TONE_MAP.muted
  if (confidence.value >= 0.8) return CONFIDENCE_TONE_MAP.high
  if (confidence.value >= 0.6) return CONFIDENCE_TONE_MAP.medium
  return CONFIDENCE_TONE_MAP.low
}

const normalizeSource = (source) => {
  const raw = source == null ? '' : String(source).trim()
  const key = raw.toLowerCase().replace(/[\s_-]+/g, '')
  if (SOURCE_LABEL_MAP[key]) return SOURCE_LABEL_MAP[key]
  if (!raw) return 'Agent'

  return raw
    .replace(/([a-z])([A-Z])/g, '$1 $2')
    .replace(/[_-]+/g, ' ')
    .trim()
    .split(/\s+/)
    .map((part) =>
      part ? part[0].toUpperCase() + part.slice(1).toLowerCase() : ''
    )
    .join(' ') || 'Agent'
}

const normalizeFinding = (finding, index) => {
  const confidence = normalizeConfidence(finding?.confidence)
  return {
    confidence,
    confidenceDisplay: confidence.display,
    confidenceKnown: confidence.known,
    tone: getConfidenceTone(confidence),
    sourceLabel: normalizeSource(finding?.source),
    findingText:
      typeof finding?.finding === 'string' && finding.finding.trim()
        ? finding.finding.trim()
        : 'Finding unavailable',
    evidenceText:
      typeof finding?.evidence === 'string' && finding.evidence.trim()
        ? finding.evidence.trim()
        : '',
    originalIndex: index,
  }
}

export default function FindingsGrid({ findings }) {
  const safeFindings = Array.isArray(findings) ? findings : []
  const normalized = safeFindings
    .filter((finding) => finding && typeof finding === 'object')
    .map(normalizeFinding)

  return (
    <div className="bg-sentinel-surface border border-sentinel-border rounded-xl p-6 shadow-lg">
      <h2 className="text-xs font-semibold text-sentinel-muted uppercase tracking-[0.1em] mb-4">
        Key Findings ({normalized.length})
      </h2>
      {normalized.length === 0 ? (
        <div className="py-8 text-center text-xs text-sentinel-muted">
          No key findings were generated for this investigation.
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {normalized.map((f) => (
            <div key={f.originalIndex} className="flex gap-4 p-4 bg-sentinel-bg rounded-xl border border-sentinel-border hover:border-sentinel-accent/50 transition-colors group">
              <div className="flex-shrink-0 text-center min-w-[50px] border-r border-sentinel-border pr-4">
                <span className={`text-xl font-bold tabular-nums ${f.tone.text}`}>
                  {f.confidenceDisplay}
                  {f.confidenceKnown && (
                    <span className="text-[10px] ml-0.5">%</span>
                  )}
                </span>
                <div className="text-[9px] text-sentinel-muted uppercase tracking-tighter mt-1">{f.sourceLabel}</div>
              </div>
              <div className="min-w-0">
                <p className="text-sm text-white font-medium leading-snug group-hover:text-sentinel-accent transition-colors">{f.findingText}</p>
                {f.evidenceText && (
                  <p className="text-[11px] text-sentinel-muted mt-2 leading-relaxed line-clamp-3 font-mono">{f.evidenceText}</p>
                )}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
