export default function ExecutiveSummary({ report }) {
  const summary = report?.executive_summary || ''
  const lowerSummary = summary.toLowerCase()
  const vector = lowerSummary.includes('ssrf') ||
    lowerSummary.includes('server-side request forgery')
    ? 'SSRF'
    : lowerSummary.includes('ransomware') ||
      lowerSummary.includes('encrypted')
      ? 'Ransomware'
      : lowerSummary.includes('powershell')
        ? 'PowerShell'
        : null
  const impact = lowerSummary.includes('iam') &&
    lowerSummary.includes('credential')
    ? 'IAM Credentials'
    : lowerSummary.includes('credential')
      ? 'Credential Exposure'
      : lowerSummary.includes('metadata')
        ? 'Metadata Service'
        : null
  const actionParts = []
  if (
    lowerSummary.includes('credential rotation') ||
    (lowerSummary.includes('rotate') && lowerSummary.includes('credential'))
  ) {
    actionParts.push('Rotate credentials')
  }
  if (lowerSummary.includes('patch')) {
    actionParts.push('Patch vulnerability')
  }
  if (lowerSummary.includes('contain')) {
    actionParts.push('Contain threat')
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
