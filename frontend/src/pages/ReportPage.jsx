import { useNavigate } from 'react-router-dom'
import { useInvestigation } from '../store/InvestigationContext'
import { Download, ArrowLeft } from 'lucide-react'
import ExecutiveSummary from '../components/report/ExecutiveSummary'
import FindingsGrid from '../components/report/FindingsGrid'
import MitreTable from '../components/report/MitreTable'
import ThreatIntelCards from '../components/report/ThreatIntelCards'
import RecommendedActions from '../components/report/RecommendedActions'
import CveList from '../components/report/CveList'

export default function ReportPage() {
  const { state } = useInvestigation()
  const navigate = useNavigate()
  const report = state.result?.final_report

  if (!report) {
    return (
      <div className="flex items-center justify-center h-[calc(100vh-57px)]">
        <div className="text-center animate-fade-in">
          <p className="text-sentinel-muted mb-4">No report available in current session</p>
          <button
            onClick={() => navigate('/')}
            className="px-6 py-2 bg-sentinel-accent text-white rounded-lg text-sm font-medium hover:bg-blue-500 transition-colors"
          >
            Start Investigation
          </button>
        </div>
      </div>
    )
  }

  const severityColors = {
    CRITICAL: 'bg-red-900/30 text-sentinel-danger border-sentinel-danger',
    HIGH: 'bg-orange-900/30 text-orange-400 border-orange-400',
    MEDIUM: 'bg-yellow-900/30 text-sentinel-warning border-sentinel-warning',
    LOW: 'bg-green-900/30 text-sentinel-success border-sentinel-success',
  }

  return (
    <div className="max-w-5xl mx-auto px-6 py-8 animate-fade-in">
      {/* Report header */}
      <div className="flex items-start justify-between mb-8">
        <div>
          <button
            onClick={() => navigate('/dashboard')}
            className="flex items-center gap-2 text-sm text-sentinel-muted hover:text-white mb-4 transition-colors group"
          >
            <ArrowLeft className="w-4 h-4 group-hover:-translate-x-1 transition-transform" /> Back to Dashboard
          </button>
          <div className="flex items-center gap-3 mb-2">
            <span className={`text-[10px] font-bold px-2.5 py-0.5 rounded-full border uppercase tracking-wider ${
              severityColors[report.severity] || severityColors.HIGH
            }`}>
              {report.severity}
            </span>
            <span className="text-[10px] font-mono text-sentinel-accent bg-blue-900/20 border border-blue-900 px-2.5 py-0.5 rounded-full uppercase tracking-wider">
              {report.classification}
            </span>
          </div>
          <h1 className="text-3xl font-bold text-white">Incident Report</h1>
          <p className="text-xs text-sentinel-muted font-mono mt-1 flex items-center gap-2">
            <span className="bg-sentinel-border px-1.5 py-0.5 rounded">{report.investigation_id || state.investigationId}</span>
            <span>·</span>
            <span>{report.generated_at ? new Date(report.generated_at).toLocaleString() : 'Just now'}</span>
          </p>
        </div>
        <div className="flex items-center gap-6">
          <div className="text-right">
            <div className="text-3xl font-bold text-sentinel-accent leading-none">
              {Math.round((report.investigation_confidence || 0) * 100)}%
            </div>
            <div className="text-[10px] text-sentinel-muted uppercase tracking-widest mt-1">confidence</div>
          </div>
          <button
            className="flex items-center gap-2 px-5 py-2.5 bg-sentinel-surface border border-sentinel-border hover:border-sentinel-accent text-white font-medium rounded-xl text-sm transition-all shadow-lg active:scale-95"
            onClick={() => alert('PDF generation coming with ReportAgent')}
          >
            <Download className="w-4 h-4 text-sentinel-accent" />
            Export PDF
          </button>
        </div>
      </div>

      {/* Report sections */}
      <div className="space-y-6">
        <ExecutiveSummary report={report} />
        <FindingsGrid findings={report.key_findings || []} />
        <RecommendedActions actions={report.recommended_actions || []} />
        <MitreTable
          techniques={report.mitre_techniques_used || []}
          ttpMappings={state.result?.ttp_mappings || []}
        />
        <ThreatIntelCards threatIntel={state.result?.threat_intel || {}} />
        <CveList cves={report.cves_identified || []} />
        
        <div className="pt-8 text-center border-t border-sentinel-border opacity-30">
          <p className="text-[10px] text-sentinel-muted uppercase tracking-[0.2em]">
            End of Automated Incident Report — Splunk Sentinel
          </p>
        </div>
      </div>
    </div>
  )
}
