export default function CveList({ cves }) {
  const normalizedCves = (cves || [])
    .map(cve => String(cve).trim())
    .filter(cve => cve.length > 0)

  if (normalizedCves.length === 0) return null

  return (
    <div
      className="bg-sentinel-surface border border-sentinel-border rounded-xl p-6 shadow-lg"
      style={{ borderTop: '2px solid #3b82f6' }}
    >
      <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between mb-4">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <div className="w-2 h-4 rounded-sm bg-sentinel-accent" />
            <h2 className="text-sm font-bold text-white tracking-wide">
              Vulnerabilities Identified
            </h2>
          </div>
          <p className="text-xs text-sentinel-muted ml-4">
            Referenced CVEs linked to mapped techniques
          </p>
        </div>
        <span className="text-xs px-2 py-1 rounded bg-sentinel-bg border border-sentinel-border text-sentinel-muted whitespace-nowrap">
          {normalizedCves.length} CVE{normalizedCves.length !== 1 ? 's' : ''}
        </span>
      </div>
      <div className="grid grid-cols-1 gap-3">
        {normalizedCves.map((cve, i) => (
          <a
            key={i}
            href={`https://nvd.nist.gov/vuln/detail/${cve}`}
            target="_blank"
            rel="noopener noreferrer"
            className="bg-sentinel-bg border border-sentinel-border rounded-lg p-3 hover:border-sentinel-accent hover:bg-sentinel-surface transition-colors"
          >
            <div className="flex items-start justify-between gap-3">
              <div className="min-w-0">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="text-xs font-mono px-1.5 py-0.5 rounded bg-blue-900/20 border border-blue-500/30 text-sentinel-accent">
                    {cve}
                  </span>
                  <span className="text-xs px-1.5 py-0.5 rounded bg-sentinel-surface border border-sentinel-border text-sentinel-muted">
                    Referenced
                  </span>
                </div>
                <p className="text-xs text-sentinel-muted mt-2 leading-relaxed">
                  Referenced by mapped MITRE techniques or remediation actions.
                </p>
              </div>
              <div className="flex flex-col items-end gap-1 shrink-0">
                <span className="text-[10px] uppercase tracking-wider text-sentinel-muted">
                  Mapped Evidence
                </span>
                <span className="text-xs font-mono text-sentinel-accent">
                  NVD -&gt;
                </span>
              </div>
            </div>
          </a>
        ))}
      </div>
      <p className="text-xs text-sentinel-muted mt-3 pt-3 border-t border-sentinel-border/40">
        Referenced vulnerabilities inform the remediation plan above.
      </p>
    </div>
  )
}
