import { useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { useInvestigation } from '../store/InvestigationContext'
import AgentStatusPanel from '../components/investigation/AgentStatusPanel'
import KillChainGraph from '../components/investigation/KillChainGraph'
import EventFeed from '../components/investigation/EventFeed'
import ConfidenceChart from '../components/investigation/ConfidenceChart'

export default function DashboardPage() {
  const { state } = useInvestigation()
  const navigate = useNavigate()

  // Redirect to report when complete
  useEffect(() => {
    if (state.status === 'complete' && state.result) {
      setTimeout(() => navigate('/report'), 1500)
    }
  }, [state.status, state.result, navigate])

  if (state.status === 'idle') {
    return (
      <div className="flex items-center justify-center h-[calc(100vh-57px)]">
        <div className="text-center">
          <p className="text-sentinel-muted mb-4">No active investigation</p>
          <button
            onClick={() => navigate('/')}
            className="px-4 py-2 bg-sentinel-accent text-white rounded-lg text-sm"
          >
            Start Investigation
          </button>
        </div>
      </div>
    )
  }

  return (
    <div className="max-w-7xl mx-auto px-6 py-6">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h2 className="text-lg font-semibold text-white">Live Investigation</h2>
          <p className="text-xs text-sentinel-muted font-mono mt-1">
            {state.investigationId}
          </p>
        </div>
        <div className="flex items-center gap-3">
          {state.status === 'running' && (
            <span className="flex items-center gap-2 text-sm text-sentinel-warning">
              <span className="w-2 h-2 bg-sentinel-warning rounded-full animate-pulse" />
              Investigating...
            </span>
          )}
          {state.status === 'complete' && (
            <span className="flex items-center gap-2 text-sm text-sentinel-success">
              <span className="w-2 h-2 bg-sentinel-success rounded-full" />
              Complete — loading report...
            </span>
          )}
        </div>
      </div>

      {/* Main grid */}
      <div className="grid grid-cols-12 gap-5">
        {/* Left: Agent status */}
        <div className="col-span-12 lg:col-span-2">
          <AgentStatusPanel />
        </div>

        {/* Center: Kill chain graph */}
        <div className="col-span-12 lg:col-span-7">
          <KillChainGraph />
        </div>

        {/* Right: Event feed */}
        <div className="col-span-12 lg:col-span-3">
          <EventFeed />
        </div>

        {/* Bottom: Confidence chart */}
        <div className="col-span-12">
          <ConfidenceChart />
        </div>
      </div>
    </div>
  )
}
