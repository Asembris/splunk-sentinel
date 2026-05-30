const CONFIDENCE_TONE_MAP = {
  high: {
    text: 'text-sentinel-success',
    border: 'border-green-500/30',
    bg: 'bg-green-500/10',
    bar: 'bg-green-500',
    leftBorder: 'border-l-green-500',
  },
  medium: {
    text: 'text-sentinel-warning',
    border: 'border-amber-500/30',
    bg: 'bg-amber-500/10',
    bar: 'bg-amber-500',
    leftBorder: 'border-l-amber-500',
  },
  low: {
    text: 'text-sentinel-danger',
    border: 'border-red-500/30',
    bg: 'bg-red-500/10',
    bar: 'bg-red-500',
    leftBorder: 'border-l-red-500',
  },
  muted: {
    text: 'text-sentinel-muted',
    border: 'border-sentinel-border',
    bg: 'bg-sentinel-surface',
    bar: 'bg-sentinel-muted',
    leftBorder: 'border-l-sentinel-border',
  },
}

const SOURCE_LABEL_MAP = {
  reconstructionagent: 'Reconstruction',
  triageagent: 'Triage',
  mitreagent: 'MITRE',
  reportagent: 'Report',
}

const EVIDENCE_CHIP_STYLE_MAP = {
  process: 'text-xs font-mono px-1.5 py-0.5 rounded border border-amber-500/30 bg-amber-900/20 text-amber-300',
  event: 'text-xs font-mono px-1.5 py-0.5 rounded border border-blue-500/30 bg-blue-900/20 text-blue-300',
  ip: 'text-xs font-mono px-1.5 py-0.5 rounded border border-cyan-500/30 bg-cyan-900/20 text-cyan-300',
  mitre: 'text-xs font-mono px-1.5 py-0.5 rounded border border-red-500/30 bg-red-900/20 text-red-300',
  credential: 'text-xs font-mono px-1.5 py-0.5 rounded border border-amber-500/30 bg-amber-900/20 text-amber-300',
  timestamp: 'text-xs font-mono px-1.5 py-0.5 rounded border border-sentinel-border bg-sentinel-surface text-sentinel-muted',
  generic: 'text-xs font-mono px-1.5 py-0.5 rounded border border-sentinel-border bg-sentinel-surface text-sentinel-muted',
}

const IP_CHIP_BLOCKLIST = new Set(['169.254.169.254'])

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

const isValidIp = (ip) => {
  const octets = ip.split('.').map(Number)
  return octets.length === 4 &&
    octets.every((octet) => Number.isInteger(octet) && octet >= 0 && octet <= 255)
}

const addChip = (chips, seen, type, label) => {
  if (!label || chips.length >= 8) return
  const key = `${type}:${label.toLowerCase()}`
  if (seen.has(key)) return
  seen.add(key)
  chips.push({ type, label })
}

const extractEvidenceChips = (text) => {
  if (!text) return []

  const chips = []
  const seen = new Set()
  const source = String(text)

  const processMatches = source.match(/\b[\w.-]+\.exe\b/gi) || []
  processMatches.forEach((match) => {
    addChip(chips, seen, 'process', match)
  })

  const eventMatches = source.matchAll(/EventCode\s+(\d{4,5})/gi)
  Array.from(eventMatches).forEach((match) => {
    addChip(chips, seen, 'event', `EventCode ${match[1]}`)
  })

  const ipMatches = source.match(/\b\d{1,3}(?:\.\d{1,3}){3}\b/g) || []
  ipMatches.forEach((match) => {
    if (!isValidIp(match) || IP_CHIP_BLOCKLIST.has(match)) return
    addChip(chips, seen, 'ip', `IP ${match}`)
  })

  const mitreMatches = source.match(/\bT\d{4}(?:\.\d{3})?\b/g) || []
  mitreMatches.forEach((match) => {
    addChip(chips, seen, 'mitre', match)
  })

  const credentialMatches = source.match(/\b(EC2InstanceRole|AccessKey|SecretKey|IAM)\b/gi) || []
  credentialMatches.forEach((match) => {
    const label = match.toLowerCase() === 'iam'
      ? 'IAM Credentials'
      : match
    addChip(chips, seen, 'credential', label)
  })

  const timestampMatches = source.match(/\b\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\b/g) || []
  timestampMatches.forEach((match) => {
    addChip(chips, seen, 'timestamp', match)
  })

  return chips
}

const normalizeFinding = (finding, index) => {
  const confidence = normalizeConfidence(finding?.confidence)
  const findingText =
    typeof finding?.finding === 'string' && finding.finding.trim()
      ? finding.finding.trim()
      : 'Finding unavailable'
  const evidenceText =
    typeof finding?.evidence === 'string' && finding.evidence.trim()
      ? finding.evidence.trim()
      : ''

  return {
    confidence,
    confidenceDisplay: confidence.display,
    confidenceKnown: confidence.known,
    tone: getConfidenceTone(confidence),
    sourceLabel: normalizeSource(finding?.source),
    findingText,
    evidenceText,
    evidenceChips: extractEvidenceChips(`${findingText} ${evidenceText}`),
    originalIndex: index,
  }
}

export default function FindingsGrid({ findings }) {
  const safeFindings = Array.isArray(findings) ? findings : []
  const normalized = safeFindings
    .filter((finding) => finding && typeof finding === 'object')
    .map(normalizeFinding)
  const uniqueSourceCount = new Set(
    normalized.map((finding) => finding.sourceLabel)
  ).size
  const highConfidenceCount = normalized.filter(
    (finding) =>
      finding.confidenceKnown && finding.confidence.value >= 0.8
  ).length

  return (
    <div className="bg-sentinel-surface border border-sentinel-border rounded-xl p-6 shadow-lg" style={{ borderTop: '2px solid #3b82f6' }}>
      <div className="flex flex-col gap-3 md:flex-row md:items-start md:justify-between mb-4">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <div className="w-2 h-4 rounded-sm bg-sentinel-accent" />
            <h2 className="text-sm font-bold text-white tracking-wide">
              Key Findings
            </h2>
          </div>
          <p className="text-xs text-sentinel-muted ml-4">
            {normalized.length} evidence-backed finding
            {normalized.length !== 1 ? 's' : ''} extracted from agent reconstruction
          </p>
        </div>
        <div className="flex items-center gap-2 flex-wrap shrink-0">
          <span className="text-xs px-2 py-1 rounded bg-sentinel-bg border border-sentinel-border text-sentinel-muted whitespace-nowrap">
            {normalized.length} finding{normalized.length !== 1 ? 's' : ''}
          </span>
          {uniqueSourceCount > 0 && (
            <span className="text-xs px-2 py-1 rounded bg-sentinel-bg border border-sentinel-border text-sentinel-muted whitespace-nowrap">
              {uniqueSourceCount} agent{uniqueSourceCount !== 1 ? 's' : ''}
            </span>
          )}
          {highConfidenceCount > 0 && (
            <span className="text-xs px-2 py-1 rounded bg-green-900/20 border border-green-500/30 text-green-400 whitespace-nowrap">
              {highConfidenceCount} high confidence
            </span>
          )}
        </div>
      </div>
      {normalized.length === 0 ? (
        <div className="py-8 text-center text-xs text-sentinel-muted">
          No key findings were generated for this investigation.
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {normalized.map((f, index) => {
            const isLastOddCard =
              index === normalized.length - 1 &&
              normalized.length % 2 === 1 &&
              normalized.length > 1

            return (
              <div
                key={f.originalIndex}
                className={`p-4 bg-sentinel-bg rounded-lg border border-sentinel-border border-l-4 ${f.tone.leftBorder} hover:border-sentinel-accent/50 hover:bg-sentinel-surface transition-colors group ${
                  isLastOddCard ? 'md:col-span-2' : ''
                }`}
              >
                <div className="flex items-start justify-between gap-3 mb-3">
                  <div className="flex items-center gap-2 flex-wrap min-w-0">
                    <span className="text-[10px] font-bold uppercase tracking-wider px-2 py-1 rounded border border-sentinel-border bg-sentinel-surface text-sentinel-muted">
                      Finding {String(index + 1).padStart(2, '0')}
                    </span>
                    {index === 0 && (
                      <span className="text-[10px] font-bold uppercase tracking-wider px-2 py-1 rounded border border-blue-500/30 bg-blue-900/20 text-blue-300">
                        Primary Finding
                      </span>
                    )}
                    <span className="text-[10px] font-bold uppercase tracking-wider px-2 py-1 rounded border border-sentinel-border bg-sentinel-surface text-sentinel-muted">
                      {f.sourceLabel}
                    </span>
                  </div>
                  <div className="text-right shrink-0">
                    <span className={`text-lg font-bold tabular-nums leading-none ${f.tone.text}`}>
                      {f.confidenceDisplay}
                      {f.confidenceKnown && (
                        <span className="text-[10px] ml-0.5">%</span>
                      )}
                    </span>
                    <div className="text-[9px] text-sentinel-muted uppercase tracking-wider mt-1">
                      Confidence
                    </div>
                  </div>
                </div>
                <p className="text-sm font-semibold text-white leading-snug group-hover:text-sentinel-accent transition-colors">
                  {f.findingText}
                </p>
                {f.evidenceChips.length > 0 && (
                  <div className="flex gap-1.5 flex-wrap mt-2">
                    {f.evidenceChips.slice(0, 4).map((chip) => (
                      <span
                        key={`${chip.type}-${chip.label}`}
                        className={EVIDENCE_CHIP_STYLE_MAP[chip.type] || EVIDENCE_CHIP_STYLE_MAP.generic}
                      >
                        {chip.label}
                      </span>
                    ))}
                    {f.evidenceChips.length > 4 && (
                      <span className={EVIDENCE_CHIP_STYLE_MAP.generic}>
                        +{f.evidenceChips.length - 4}
                      </span>
                    )}
                  </div>
                )}
                {f.evidenceText && (
                  <p className="text-xs font-mono text-sentinel-muted mt-2 leading-relaxed line-clamp-3">{f.evidenceText}</p>
                )}
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}
