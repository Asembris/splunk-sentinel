export default function CveList({ cves }) {
  if (!cves || cves.length === 0) return null

  return (
    <div className="bg-sentinel-surface border border-sentinel-border rounded-xl p-6 shadow-lg">
      <h2 className="text-xs font-semibold text-sentinel-muted uppercase tracking-[0.1em] mb-4">
        Vulnerabilities Identified
      </h2>
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
