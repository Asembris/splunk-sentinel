export default function CveList({ cves }) {
  if (!cves || cves.length === 0) return null

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
          {cves.length} CVE{cves.length !== 1 ? 's' : ''}
        </span>
      </div>
      <div className="flex flex-wrap gap-3">
        {cves.map((cve, i) => (
          <a
            key={i}
            href={`https://nvd.nist.gov/vuln/detail/${cve}`}
            target="_blank"
            rel="noopener noreferrer"
            className="text-xs font-mono px-4 py-2 bg-sentinel-bg border border-sentinel-border hover:border-sentinel-accent text-sentinel-accent rounded-lg transition-all hover:scale-105 shadow-sm flex items-center gap-2"
          >
            <span className="w-1.5 h-1.5 rounded-full bg-sentinel-accent" />
            {cve}
          </a>
        ))}
      </div>
    </div>
  )
}
