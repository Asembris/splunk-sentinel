import { useParams, useNavigate } from 'react-router-dom'
import { useState, useEffect } from 'react'
import { useInvestigation } from '../store/InvestigationContext'
import { 
  Download, ArrowLeft, FileJson, Printer, 
  Share2, Loader2, AlertCircle 
} from 'lucide-react'
import ExecutiveSummary from '../components/report/ExecutiveSummary'
import FindingsGrid from '../components/report/FindingsGrid'
import MitreTable from '../components/report/MitreTable'
import ThreatIntelCards from '../components/report/ThreatIntelCards'
import RecommendedActions from '../components/report/RecommendedActions'
import CveList from '../components/report/CveList'

export default function ReportPage() {
  const { id } = useParams()
  const { state } = useInvestigation()
  const navigate = useNavigate()
  
  const [historicalData, setHistoricalData] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)

  // Use state.result if available, otherwise use historicalData
  const activeResult = state.result || historicalData
  const report = activeResult?.final_report

  useEffect(() => {
    // If we have an ID in the URL and no live state, fetch from backend
    if (id && !state.result) {
      const fetchHistoricalReport = async () => {
        setLoading(true)
        setError(null)
        try {
          const res = await fetch(`/api/investigations/${id}`)
          if (!res.ok) {
            if (res.status === 404) throw new Error('Investigation not found')
            throw new Error('Failed to fetch historical report')
          }
          const data = await res.json()
          setHistoricalData(data)
        } catch (err) {
          console.error('Report fetch error:', err)
          setError(err.message)
        } finally {
          setLoading(false)
        }
      }
      fetchHistoricalReport()
    }
  }, [id, state.result])

  const handleExportJson = () => {
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(activeResult, null, 2));
    const downloadAnchorNode = document.createElement('a');
    downloadAnchorNode.setAttribute("href",     dataStr);
    downloadAnchorNode.setAttribute("download", `sentinel-report-${id || state.investigationId}.json`);
    document.body.appendChild(downloadAnchorNode);
    downloadAnchorNode.click();
    downloadAnchorNode.remove();
  }

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center h-[calc(100vh-57px)]">
        <Loader2 className="w-10 h-10 text-sentinel-accent animate-spin mb-4" />
        <p className="text-sentinel-muted animate-pulse">Retrieving historical report...</p>
      </div>
    )
  }

  if (error) {
    return (
      <div className="flex flex-col items-center justify-center h-[calc(100vh-57px)]">
        <div className="bg-red-500/10 border border-red-500/20 p-8 rounded-2xl text-center max-w-md">
          <AlertCircle className="w-12 h-12 text-red-400 mx-auto mb-4" />
          <h2 className="text-xl font-bold text-white mb-2">Report Error</h2>
          <p className="text-sentinel-muted mb-6">{error}</p>
          <button
            onClick={() => navigate('/history')}
            className="px-6 py-2 bg-sentinel-surface border border-sentinel-border hover:border-red-500/50 text-white rounded-lg transition-all"
          >
            Return to History
          </button>
        </div>
      </div>
    )
  }

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
          <h1 className="text-3xl font-bold text-white tracking-tight">Automated Investigation Report</h1>
          <p className="text-xs text-sentinel-muted font-mono mt-1 flex items-center gap-2">
            <span className="bg-sentinel-border px-1.5 py-0.5 rounded text-gray-400">{report.investigation_id || state.investigationId}</span>
            <span>·</span>
            <span>{report.generated_at ? new Date(report.generated_at).toLocaleString() : 'Just now'}</span>
          </p>
        </div>
        <div className="flex items-center gap-4">
          <div className="text-right mr-4 border-r border-sentinel-border pr-6">
            <div className="text-3xl font-bold text-sentinel-accent leading-none">
              {Math.round((report.investigation_confidence || 0) * 100)}%
            </div>
            <div className="text-[10px] text-sentinel-muted uppercase tracking-widest mt-1">confidence</div>
          </div>
          <div className="flex gap-2">
            <button
              onClick={handleExportJson}
              className="p-2.5 bg-sentinel-surface border border-sentinel-border hover:border-sentinel-accent text-white rounded-xl transition-all shadow-lg active:scale-95 group"
              title="Download JSON"
            >
              <FileJson className="w-5 h-5 text-sentinel-accent group-hover:scale-110 transition-transform" />
            </button>
            <button
              className="flex items-center gap-2 px-5 py-2.5 bg-sentinel-accent hover:bg-blue-500 text-white font-semibold rounded-xl text-sm transition-all shadow-lg active:scale-95 disabled:opacity-50 disabled:cursor-not-allowed"
              onClick={() => alert('PDF report is being generated by ReportAgent... Check back in 30s.')}
              disabled
            >
              <Download className="w-4 h-4" />
              Export PDF
            </button>
          </div>
        </div>
      </div>

      {/* Report sections */}
      <div className="space-y-6">
        <ExecutiveSummary report={report} />
        <FindingsGrid findings={report.key_findings || []} />
        <RecommendedActions actions={report.recommended_actions || []} />
        <MitreTable
          techniques={report.mitre_techniques_used || []}
          ttpMappings={activeResult?.ttp_mappings || []}
        />
        <ThreatIntelCards threatIntel={activeResult?.threat_intel || {}} />
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
