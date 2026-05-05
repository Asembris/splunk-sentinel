import { useInvestigation } from '../store/InvestigationContext'
import { useNavigate } from 'react-router-dom'
import { Clock, Shield, ChevronRight } from 'lucide-react'

export default function HistoryPage() {
  const { state } = useInvestigation()
  const navigate = useNavigate()

  const hasHistory = state.result !== null

  return (
    <div className="max-w-5xl mx-auto px-6 py-8 animate-fade-in">
      <div className="flex items-center justify-between mb-8">
        <div>
          <h1 className="text-2xl font-bold text-white">Investigation History</h1>
          <p className="text-sm text-sentinel-muted mt-1">Review past autonomous investigations from this session.</p>
        </div>
        <div className="bg-sentinel-surface px-4 py-2 rounded-xl border border-sentinel-border flex items-center gap-3">
          <Clock className="w-4 h-4 text-sentinel-accent" />
          <span className="text-xs font-bold text-white">{hasHistory ? '1 Record' : '0 Records'}</span>
        </div>
      </div>

      {!hasHistory ? (
        <div className="text-center py-24 bg-sentinel-surface border border-sentinel-border border-dashed rounded-3xl">
          <div className="w-16 h-16 bg-sentinel-bg border border-sentinel-border rounded-2xl flex items-center justify-center mx-auto mb-4">
            <Clock className="w-8 h-8 text-sentinel-muted/50" />
          </div>
          <h2 className="text-lg font-bold text-white mb-2">No session history found</h2>
          <p className="text-sentinel-muted text-sm mb-6 max-w-xs mx-auto">Start an investigation to generate a report and see it listed here.</p>
          <button
            onClick={() => navigate('/')}
            className="px-6 py-2.5 bg-sentinel-accent text-white rounded-xl text-sm font-semibold hover:bg-blue-500 transition-colors shadow-lg shadow-blue-900/20"
          >
            Start Investigation
          </button>
        </div>
      ) : (
        <div className="space-y-4">
          {/* Show current session investigation */}
          {state.result && (
            <div
              className="flex items-center justify-between p-5 bg-sentinel-surface border border-sentinel-border hover:border-sentinel-accent rounded-2xl cursor-pointer transition-all hover:translate-x-1 group shadow-xl"
              onClick={() => navigate('/report')}
            >
              <div className="flex items-center gap-5">
                <div className="w-12 h-12 bg-sentinel-bg border border-sentinel-border rounded-xl flex items-center justify-center group-hover:border-sentinel-accent transition-colors">
                  <Shield className="w-6 h-6 text-sentinel-accent" />
                </div>
                <div>
                  <div className="flex items-center gap-3 mb-1.5">
                    <span className="text-[10px] font-black text-sentinel-danger px-2 py-0.5 bg-red-900/20 border border-sentinel-danger rounded uppercase tracking-widest">
                      {state.result.final_report?.severity || 'HIGH'}
                    </span>
                    <span className="text-[10px] font-mono text-sentinel-accent uppercase tracking-tighter">
                      {state.result.attack_classification}
                    </span>
                  </div>
                  <p className="text-sm text-white font-bold leading-tight group-hover:text-sentinel-accent transition-colors">
                    {state.trigger?.slice(0, 75)}...
                  </p>
                  <p className="text-[10px] text-sentinel-muted font-mono mt-1.5 opacity-60">
                    ID: {state.investigationId} · COMPLETED JUST NOW
                  </p>
                </div>
              </div>
              <div className="flex items-center gap-6">
                <div className="text-right">
                  <div className="text-xl font-bold text-sentinel-accent tabular-nums">
                    {Math.round((state.result.final_report?.investigation_confidence || 0) * 100)}%
                  </div>
                  <div className="text-[9px] text-sentinel-muted uppercase tracking-widest mt-0.5">confidence</div>
                </div>
                <ChevronRight className="w-5 h-5 text-sentinel-muted group-hover:text-white transition-colors" />
              </div>
            </div>
          )}
          
          <div className="mt-12 p-6 border border-sentinel-border border-dashed rounded-2xl bg-sentinel-surface/30">
            <div className="flex items-center gap-3 text-sentinel-muted">
              <div className="p-2 bg-sentinel-bg rounded-lg border border-sentinel-border">
                <Clock className="w-4 h-4 opacity-50" />
              </div>
              <div className="text-xs italic leading-relaxed">
                Persistent database history (Supabase) is scheduled for the <span className="text-sentinel-accent font-bold">ReportAgent</span> deployment phase. Currently showing session-only investigation.
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
