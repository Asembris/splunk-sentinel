import { useEffect, useRef } from 'react'
import { Network } from 'vis-network'
import { DataSet } from 'vis-data'
import { useInvestigation } from '../../store/InvestigationContext'

const TACTIC_COLORS = {
  'TA0001': '#ef4444', // Initial Access — red
  'TA0002': '#f97316', // Execution — orange
  'TA0003': '#eab308', // Persistence — yellow
  'TA0004': '#a855f7', // Privilege Escalation — purple
  'TA0005': '#6366f1', // Defense Evasion — indigo
  'TA0006': '#ec4899', // Credential Access — pink
  'TA0007': '#14b8a6', // Discovery — teal
  'TA0008': '#f59e0b', // Lateral Movement — amber
  'TA0009': '#84cc16', // Collection — lime
  'TA0010': '#06b6d4', // Exfiltration — cyan
  'TA0011': '#8b5cf6', // Command and Control — violet
  'TA0040': '#dc2626', // Impact — dark red
}

function getNodeColor(stageName) {
  for (const [tactic, color] of Object.entries(TACTIC_COLORS)) {
    if (stageName.includes(tactic)) return color
  }
  // Infer from stage name keywords
  if (stageName.toLowerCase().includes('initial') || stageName.toLowerCase().includes('access')) return TACTIC_COLORS['TA0001']
  if (stageName.toLowerCase().includes('execut')) return TACTIC_COLORS['TA0002']
  if (stageName.toLowerCase().includes('credential') || stageName.toLowerCase().includes('iam')) return TACTIC_COLORS['TA0006']
  if (stageName.toLowerCase().includes('lateral')) return TACTIC_COLORS['TA0008']
  if (stageName.toLowerCase().includes('evasion') || stageName.toLowerCase().includes('log')) return TACTIC_COLORS['TA0005']
  if (stageName.toLowerCase().includes('impact') || stageName.toLowerCase().includes('encrypt')) return TACTIC_COLORS['TA0040']
  return '#3b82f6'
}

const VIS_OPTIONS = {
  nodes: {
    shape: 'box',
    margin: { top: 10, bottom: 10, left: 14, right: 14 },
    font: { color: '#f9fafb', size: 13, face: 'Inter, system-ui' },
    borderWidth: 2,
    shadow: { enabled: true, color: 'rgba(0,0,0,0.5)', size: 8 },
  },
  edges: {
    arrows: { to: { enabled: true, scaleFactor: 0.8 } },
    color: { color: '#374151', highlight: '#3b82f6' },
    smooth: { type: 'cubicBezier', forceDirection: 'horizontal' },
    font: { color: '#6b7280', size: 11 },
    width: 2,
  },
  layout: {
    hierarchical: {
      enabled: true,
      direction: 'LR',
      sortMethod: 'directed',
      nodeSpacing: 140,
      levelSeparation: 200,
    },
  },
  physics: { enabled: false },
  interaction: {
    hover: true,
    tooltipDelay: 200,
    zoomView: true,
    dragView: true,
  },
}

export default function KillChainGraph() {
  const { state } = useInvestigation()
  const containerRef = useRef(null)
  const networkRef = useRef(null)
  const nodesRef = useRef(new DataSet([]))
  const edgesRef = useRef(new DataSet([]))
  const stageCountRef = useRef(0)

  // Initialize network
  useEffect(() => {
    if (!containerRef.current) return

    networkRef.current = new Network(
      containerRef.current,
      { nodes: nodesRef.current, edges: edgesRef.current },
      VIS_OPTIONS
    )

    return () => {
      networkRef.current?.destroy()
      networkRef.current = null
    }
  }, [])

  // Add nodes as stages are discovered
  useEffect(() => {
    const stages = state.killChainStages
    if (stages.length <= stageCountRef.current) return

    const newStages = stages.slice(stageCountRef.current)
    const totalOldCount = stageCountRef.current
    stageCountRef.current = stages.length

    newStages.forEach((stage, i) => {
      const nodeId = stage.id
      const prevNodeId = stages[totalOldCount + i - 1]?.id

      const color = getNodeColor(stage.label)

      nodesRef.current.add({
        id: nodeId,
        label: stage.label.replace(/\s*[-–]\s*/g, '\n'),
        color: {
          background: color + '33', // 20% opacity background
          border: color,
          highlight: { background: color + '66', border: color },
          hover: { background: color + '55', border: color },
        },
        title: `Discovered in iteration ${stage.iteration}`,
        level: totalOldCount + i,
      })

      // Add edge from previous node
      if (prevNodeId) {
        edgesRef.current.add({
          id: `edge-${prevNodeId}-${nodeId}`,
          from: prevNodeId,
          to: nodeId,
        })
      }

    })

    // Fit graph after adding nodes (debounced to avoid jank)
    const timer = setTimeout(() => {
      if (networkRef.current) {
        networkRef.current.fit({ 
          animation: { duration: 1000, easingFunction: 'easeInOutQuad' } 
        })
      }
    }, 200)

    return () => clearTimeout(timer)
  }, [state.killChainStages])

  const isEmpty = state.killChainStages.length === 0
  const isIdle = state.status === 'idle'

  return (
    <div className="bg-sentinel-surface border border-sentinel-border rounded-xl overflow-hidden relative shadow-lg" style={{ height: '420px' }}>
      <div className="flex items-center justify-between px-4 py-3 border-b border-sentinel-border bg-sentinel-surface/50 backdrop-blur-sm z-10 relative">
        <h3 className="text-sm font-semibold text-sentinel-muted uppercase tracking-wider">
          Kill Chain Reconstruction
        </h3>
        <span className="text-xs text-sentinel-muted font-mono">
          {state.killChainStages.length} nodes
        </span>
      </div>

      <div ref={containerRef} className="w-full h-full absolute inset-0 pt-10" />

      {/* Empty state overlay */}
      {(isEmpty || isIdle) && (
        <div className="absolute inset-0 flex items-center justify-center pointer-events-none z-20">
          <div className="text-center">
            <div className="w-12 h-12 border-2 border-sentinel-border rounded-full flex items-center justify-center mx-auto mb-3 animate-pulse">
              <span className="text-sentinel-muted text-xl">⬡</span>
            </div>
            <p className="text-sentinel-muted text-sm px-10">
              {isIdle ? 'Start an investigation to see the kill chain' : 'Reconstructing attack lifecycle...'}
            </p>
          </div>
        </div>
      )}
    </div>
  )
}
