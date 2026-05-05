const LEVEL_COLORS = {
  CRITICAL: 'border-sentinel-danger text-sentinel-danger bg-red-900/10',
  HIGH:     'border-orange-500 text-orange-400 bg-orange-900/10',
  MEDIUM:   'border-sentinel-warning text-sentinel-warning bg-yellow-900/10',
  LOW:      'border-sentinel-success text-sentinel-success bg-green-900/10',
}

export default function ThreatIntelCards({ threatIntel }) {
  const entries = Object.entries(threatIntel || {})
  if (entries.length === 0) return null

  return (
    <div className="bg-sentinel-surface border border-sentinel-border rounded-xl p-6 shadow-lg">
      <h2 className="text-xs font-semibold text-sentinel-muted uppercase tracking-[0.1em] mb-4">
        External Threat Intelligence
      </h2>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {entries.map(([ip, data]) => {
          const level = data.threat_level || 'LOW'
          return (
            <div key={ip} className={`rounded-xl border p-4 transition-all hover:shadow-lg ${LEVEL_COLORS[level]}`}>
              <div className="flex items-center justify-between mb-4">
                <div className="flex items-center gap-2">
                  <span className="w-2 h-2 rounded-full bg-current animate-pulse" />
                  <span className="font-mono font-bold text-white text-sm">{ip}</span>
                </div>
                <span className={`text-[10px] font-black px-2 py-0.5 rounded border border-current uppercase tracking-widest`}>
                  {level}
                </span>
              </div>
              <div className="grid grid-cols-2 gap-y-3 gap-x-4 text-[10px] uppercase tracking-wider mb-4 border-b border-white/10 pb-4">
                <div className="flex flex-col gap-1">
                  <span className="text-white/40">VirusTotal</span>
                  <span className="text-white font-bold">{data.virustotal?.malicious_count || 0} detections</span>
                </div>
                <div className="flex flex-col gap-1 text-right">
                  <span className="text-white/40">AbuseIPDB</span>
                  <span className="text-white font-bold">{data.abuseipdb?.abuse_confidence_score || 0}% score</span>
                </div>
                <div className="flex flex-col gap-1">
                  <span className="text-white/40">Geo/ISP</span>
                  <span className="text-white font-bold truncate">{data.abuseipdb?.country_code || '--'} · {data.abuseipdb?.isp || 'Unknown'}</span>
                </div>
                <div className="flex flex-col gap-1 text-right">
                  <span className="text-white/40">Classification</span>
                  <span className="text-white font-bold">{data.abuseipdb?.usage_type || 'Consumer'}</span>
                </div>
              </div>
              <p className="text-[11px] leading-relaxed text-white/80 antialiased">
                {data.summary || 'No detailed analysis summary available for this indicator.'}
              </p>
            </div>
          )
        })}
      </div>
    </div>
  )
}
