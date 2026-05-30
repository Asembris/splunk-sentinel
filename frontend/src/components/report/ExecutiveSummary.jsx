export default function ExecutiveSummary({ report }) {
  const summary = report?.executive_summary || ''
  const lowerSummary = summary.toLowerCase()
  const classification = (report?.classification || '')
    .toString()
    .trim()
    .toUpperCase()
    .replace(/[\s-]+/g, '_')
  const isRansomware = classification === 'RANSOMWARE' ||
    lowerSummary.includes('ransomware') ||
    lowerSummary.includes('shadow copy') ||
    lowerSummary.includes('vssadmin') ||
    lowerSummary.includes('pre-encryption')
  const isInsiderThreat = classification === 'INSIDER_THREAT'
  const isUnknown = classification === 'UNKNOWN'
  const vector = isRansomware
    ? 'Ransomware'
    : isInsiderThreat
      ? 'Insider Threat'
      : isUnknown
        ? 'Unconfirmed'
        : lowerSummary.includes('ssrf') ||
          lowerSummary.includes('server-side request forgery')
          ? 'SSRF'
          : classification === 'APT'
            ? 'APT Intrusion'
            : lowerSummary.includes('powershell')
              ? 'PowerShell'
              : null
  const impact = isRansomware
    ? 'Data Loss Risk'
    : isInsiderThreat
      ? 'Privilege Abuse'
      : isUnknown
        ? 'Needs Review'
        : lowerSummary.includes('iam') &&
          lowerSummary.includes('credential')
          ? 'IAM Credentials'
          : lowerSummary.includes('credential')
            ? 'Credential Exposure'
            : lowerSummary.includes('metadata')
              ? 'Metadata Service'
              : null
  const actionParts = []
  if (isUnknown) {
    actionParts.push('Escalate to analyst')
  } else if (isRansomware) {
    if (
      lowerSummary.includes('network isolation') ||
      lowerSummary.includes('isolate')
    ) {
      actionParts.push('Isolate network')
    }
    if (lowerSummary.includes('contain')) {
      actionParts.push('Contain spread')
    }
    if (
      lowerSummary.includes('credential rotation') ||
      (lowerSummary.includes('rotate') && lowerSummary.includes('credential'))
    ) {
      actionParts.push('Rotate credentials')
    }
    if (actionParts.length === 0) {
      actionParts.push('Contain spread')
    }
  } else if (isInsiderThreat) {
    if (lowerSummary.includes('disable')) {
      actionParts.push('Disable access')
    }
    actionParts.push('Review activity')
  } else if (
    lowerSummary.includes('credential rotation') ||
    (lowerSummary.includes('rotate') && lowerSummary.includes('credential'))
  ) {
    actionParts.push('Rotate credentials')
    if (lowerSummary.includes('patch')) {
      actionParts.push('Patch vulnerability')
    }
    if (lowerSummary.includes('contain')) {
      actionParts.push('Contain threat')
    }
  } else {
    if (lowerSummary.includes('patch')) {
      actionParts.push('Patch vulnerability')
    }
    if (lowerSummary.includes('contain')) {
      actionParts.push('Contain threat')
    }
  }
  const action = actionParts.length > 0
    ? actionParts.slice(0, 2).join(' + ')
    : null
  const briefFacts = [
    vector ? { label: 'Vector', value: vector } : null,
    impact ? { label: 'Impact', value: impact } : null,
    action ? { label: 'Action', value: action } : null,
  ].filter(Boolean)

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
      {briefFacts.length > 0 && (
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 mb-4">
          {briefFacts.map(fact => (
            <div
              key={fact.label}
              className="bg-sentinel-bg border border-sentinel-border rounded-lg px-3 py-2"
            >
              <p className="text-[10px] font-bold text-sentinel-muted uppercase tracking-wider mb-1">
                {fact.label}
              </p>
              <p className="text-sm font-semibold text-white leading-tight">
                {fact.value}
              </p>
            </div>
          ))}
        </div>
      )}
      <div className="bg-sentinel-bg rounded-lg px-4 py-3 mt-3">
        <div className="flex items-center gap-2 mb-2">
          <div className="w-1.5 h-1.5 rounded-full bg-sentinel-accent" />
          <span className="text-[10px] font-bold text-sentinel-muted uppercase tracking-wider">
            Incident Narrative
          </span>
        </div>
        <p className="text-white text-sm leading-relaxed antialiased">
          {report.executive_summary}
        </p>
      </div>
      {report.threat_actor_profile && (
        <div className="mt-5 pt-5 border-t border-sentinel-border/50">
          <div className="bg-sentinel-bg rounded-lg px-4 py-3">
            <div className="flex items-center gap-2 mb-2">
              <div className="w-1.5 h-1.5 rounded-full bg-sentinel-accent" />
              <span className="text-[10px] font-bold text-sentinel-muted uppercase tracking-wider">
                Threat Actor Profile
              </span>
            </div>
            <p className="text-xs text-sentinel-muted leading-relaxed">
              {report.threat_actor_profile}
            </p>
          </div>
        </div>
      )}
    </div>
  )
}
